# OpenFlow 1.1 no POX — Guia de Conceitos

> Universidade de Caxias do Sul — Redes de Computadores
> Prof.ª Maria de Fátima · Acadêmicos: Gabriel Vieira e Rafael Graunke
>
> Documento **didático**. Objetivo: entender *o que* vamos construir e *por quê*,
> antes de escrever qualquer linha de código. A implementação vem depois.

---

## 1. O cenário geral: SDN e o plano de controle

Numa rede tradicional, cada switch/roteador é uma caixa fechada que decide
sozinha como encaminhar pacotes (algoritmos de roteamento rodam *dentro* do
equipamento). O **plano de controle** (a inteligência: "para onde mando este
pacote?") e o **plano de dados** (o trabalho braçal: "copiar bytes da porta A
para a porta B") vivem juntos no mesmo hardware.

**SDN (Software Defined Networking)** separa essas duas coisas:

```
        ┌──────────────────────────────┐
        │   CONTROLADOR (plano controle)│   ← "cérebro", software (POX)
        │   decide as regras            │
        └───────────────┬──────────────┘
                        │  protocolo OpenFlow (TCP)
        ┌───────────────┴──────────────┐
        │   SWITCH (plano de dados)     │   ← só obedece, encaminha rápido
        │   tabela de fluxos            │
        └──────────────────────────────┘
```

O switch vira "burro": ele só tem uma **tabela de fluxos** (flow table). Quando
chega um pacote que ele não sabe tratar, ele pergunta ao controlador
(mensagem `PacketIn`). O controlador responde instalando uma **regra de fluxo**
(mensagem `FlowMod`) que diz: "pacotes assim → faça isto". O canal entre os dois
é o protocolo **OpenFlow**, rodando sobre TCP (porta 6633 por padrão no POX).

POX é exatamente esse controlador, escrito 100% em Python.

---

## 2. Anatomia de uma regra de fluxo (Flow Entry)

Uma entrada na tabela de fluxos tem, simplificadamente, duas partes:

1. **Match** — o critério ("quando o pacote casa com isto"). Ex.: porta de
   entrada 1, MAC destino X, tipo IPv4, etc.
2. **O que fazer** — a parte que muda entre OpenFlow 1.0 e 1.1, e é o coração
   deste trabalho.

```
┌─────────────────────────────┬──────────────────────────────┐
│  MATCH (critério de seleção) │  O QUE FAZER (ações/instruções)│
└─────────────────────────────┴──────────────────────────────┘
```

A mensagem que instala isso no switch é a `OFPT_FLOW_MOD` (Flow Modification).

---

## 3. O ponto-chave: Ações vs. Instruções (OF 1.0 vs OF 1.1)

Esta é a ideia central do projeto. **Leia com calma.**

### OpenFlow 1.0 — lista direta de Ações

No OF 1.0, a `FlowMod` carrega uma **lista plana de ações**. "Casou o match?
Execute esta sequência de ações." Uma ação típica é `OFPAT_OUTPUT` (manda o
pacote por uma porta).

```
FlowMod 1.0:
   [ header ][ match ][ campos... ][ Action OUTPUT ][ Action OUTPUT ]...
                                    └─── lista plana de ações ───┘
```

No código atual do POX isso está visível em `libopenflow_01.py`. Veja como o
`pack()` do `ofp_flow_mod` simplesmente empacota o cabeçalho, o match, os campos
e **concatena as ações uma atrás da outra** (`libopenflow_01.py:2348-2349`):

```python
for i in self.actions:
    packed += i.pack()
```

E uma ação de saída (`ofp_action_output`, `libopenflow_01.py:1579-1588`) tem só
8 bytes: tipo, tamanho, porta, max_len.

```python
packed += struct.pack("!HHHH", self.type, len(self), self.port, self.max_len)
```

Simples: a ação está **solta**, no nível de cima.

### OpenFlow 1.1 — Instruções que encapsulam Ações

A partir do 1.1 surgiu o conceito de **múltiplas tabelas** (pipeline de tabelas)
e, junto, uma nova hierarquia: a `FlowMod` não carrega mais ações diretamente —
ela carrega **Instruções** (`Instructions`). As ações ficam **dentro** de uma
instrução.

A instrução mais comum é `OFPIT_APPLY_ACTIONS`: "aplique agora este conjunto de
ações". E dentro dela é que mora o `OUTPUT`.

```
FlowMod 1.1:
   [ header ][ match ][ campos... ][ Instruction APPLY_ACTIONS ]
                                       └──────────────┬───────────┘
                                          dentro dela:
                                          [ Action OUTPUT ][ Action OUTPUT ]...
```

Ou seja, ganhamos **um nível de aninhamento**:

```
        OF 1.0                        OF 1.1
   FlowMod                       FlowMod
     └── Action OUTPUT             └── Instruction (APPLY_ACTIONS)
     └── Action OUTPUT                   └── Action OUTPUT
                                         └── Action OUTPUT
```

**Por que isso importa?** Com múltiplas tabelas, o switch precisa saber *o que
fazer entre uma tabela e outra*: aplicar ações agora? acumular ações para depois?
mandar para a próxima tabela (`OFPIT_GOTO_TABLE`)? escrever metadados? Cada uma
dessas decisões é uma **Instrução**. A lista de ações pura do 1.0 não conseguia
expressar isso. As Instruções são a "gramática" que organiza as ações num
pipeline.

> **Nosso escopo:** vamos implementar apenas `OFPIT_APPLY_ACTIONS` contendo um
> `OFPAT_OUTPUT`. É o suficiente para instalar um fluxo simples ("porta 1 →
> porta 2") usando a hierarquia nova do 1.1. Não faremos múltiplas tabelas,
> grupos, meters, nem o handshake completo do 1.1.

---

## 4. O layout binário (o que realmente vai no fio)

OpenFlow é um protocolo binário: cada estrutura é uma sequência exata de bytes,
em **network byte order** (big-endian). É isso que veremos no Wireshark. Vamos
desenhar as três estruturas que o trabalho cita.

### 4.1 `ofp_action_output` — a ação de saída (16 bytes)

Esta é a folha da árvore. **Atenção: mudou do 1.0 para o 1.1.** No 1.0 a porta
era de 16 bits e a ação tinha 8 bytes. No 1.1 a porta cresceu para **32 bits**,
então a ação tem **16 bytes** (com 6 bytes de padding para manter o alinhamento
de 8 bytes).

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌───────────────────────────────┬───────────────────────────────┐
│   type = OFPAT_OUTPUT (0)      │      len = 16                  │   ← 16+16 bits
├───────────────────────────────┴───────────────────────────────┤
│                    port (porta de saída, 32 bits)              │   ← 32 bits
├───────────────────────────────┬───────────────────────────────┤
│   max_len (16 bits)           │   padding (parte dos 48 bits)  │
├───────────────────────────────┴───────────────────────────────┤
│                  padding restante (total 6 bytes)             │
└────────────────────────────────────────────────────────────────┘
   formato struct: "!HHIH6x"   →   type, len, port(32b), max_len, 6 pad = 16 bytes
```

### 4.2 `ofp_instruction` — o cabeçalho genérico de instrução (4 bytes)

Toda instrução começa com este cabeçalho comum. **É a estrutura nova que não
existe no `libopenflow_01.py`.**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌───────────────────────────────┬───────────────────────────────┐
│   type (16 bits)               │      len (16 bits)            │
└───────────────────────────────┴───────────────────────────────┘
   type = OFPIT_APPLY_ACTIONS (= 4 no OF 1.1)
   len  = tamanho TOTAL da instrução, incluindo as ações lá dentro
```

### 4.3 `ofp_instruction_actions` — instrução que carrega ações

É o `ofp_instruction` + um padding + a lista de ações. O `OFPIT_APPLY_ACTIONS`
usa exatamente esta forma.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌───────────────────────────────┬───────────────────────────────┐
│   type = 4 (APPLY_ACTIONS)     │      len (total)              │   ← cabeçalho (4 bytes)
├───────────────────────────────┴───────────────────────────────┤
│                    padding (32 bits / 4 bytes = zeros)         │   ← alinhamento
├────────────────────────────────────────────────────────────────┤
│                                                                │
│              ações aqui dentro (ex.: ofp_action_output)        │   ← N bytes
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

**Por que o padding de 4 bytes?** OpenFlow exige que estruturas fiquem alinhadas
em fronteiras de 8 bytes. O cabeçalho da instrução tem 4 bytes; sozinho ele
desalinharia o que vem depois. Os 4 bytes de zeros empurram a primeira ação para
um offset múltiplo de 8. Detalhe pequeno, mas se errar, o switch rejeita a
mensagem.

### Montando tudo: a hierarquia final no fio

```
OFPT_FLOW_MOD
  └─ ofp_instruction_actions (type=APPLY_ACTIONS, len=24)
       ├─ padding (4 bytes zero)
       └─ ofp_action_output (type=OUTPUT, len=16, port=2, max_len=0)

bytes:  00 04 00 18   00 00 00 00   00 00 00 10   00 00 00 02   00 00   00 00 00 00 00 00
        └─instr.hdr┘  └─padding──┘  └ out: type len ┘ └ port(32b) ┘ max_len  └─ pad 6 ─┘

(len 0x18 = 24 bytes no total; a ação OUTPUT são 16 bytes; 0x10 = 16)
```

É essa árvore — `FlowMod → Instructions → Apply_Actions → Action_Output` — que
queremos ver capturada no Wireshark como prova de funcionamento.

---

## 5. Como o POX "empacota" estruturas (o padrão `pack()`)

Para implementar, basta seguir a convenção que o POX já usa em todo o
`libopenflow_01.py`. Cada estrutura é uma classe Python com:

- `__init__` — define os campos com valores padrão.
- `pack()` — devolve os **bytes** da estrutura, usando `struct.pack("!...", ...)`.
  O `!` = big-endian; `H` = 16 bits; `L` = 32 bits; `Q` = 64 bits.
- `unpack(raw, offset)` — o caminho inverso (lê bytes → preenche campos). Para a
  nossa prova de conceito (controlador *envia*), o `pack()` é o essencial.
- `__len__` — tamanho em bytes.

O segredo do aninhamento é simples: o `pack()` da instrução chama o `pack()` das
ações que ela contém e **concatena**. É o mesmo padrão recursivo da biblioteca de
pacotes do POX (`packet_base.pack()`), só que aplicado às mensagens OpenFlow:

```python
# pseudocódigo do que vamos escrever
class ofp_instruction_actions:
    def pack(self):
        corpo = b""
        for a in self.actions:        # cada ação...
            corpo += a.pack()         # ...vira bytes
        comprimento = 8 + len(corpo)  # 4 (hdr) + 4 (padding) + ações
        cabecalho = struct.pack("!HH", self.type, comprimento)
        padding   = b"\x00\x00\x00\x00"
        return cabecalho + padding + corpo
```

Repare: o campo `len` **só pode ser calculado depois** de empacotar as ações,
porque depende do tamanho delas. Esse é o tipo de detalhe que vale entender antes
de codar.

---

## 6. O que vamos construir (visão de alto nível)

Dois arquivos novos, sem tocar no `libopenflow_01.py` (coexistência):

1. **`pox/openflow/libopenflow_11.py`** — biblioteca nova. Define as classes:
   - `ofp_instruction` (cabeçalho genérico, 4 bytes),
   - `ofp_instruction_actions` / `OFPIT_APPLY_ACTIONS` (encapsula ações),
   - e reaproveita/reescreve o `ofp_action_output` (8 bytes).
   - Cada uma com seu `pack()`.

2. **`ext/of11_instruction_poc.py`** — componente de prova de conceito. Quando um
   switch conecta (`ConnectionUp`), ele monta uma `FlowMod` no formato 1.1
   (com a hierarquia instrução→ação) e envia ao switch.

### Como validar

```
Mininet (cria topologia virtual: hosts + Open vSwitch)
        │
        ▼
Open vSwitch  ←──conecta──►  POX + nosso componente PoC
        │                          │ envia FlowMod 1.1
        ▼                          ▼
   regra instalada          Wireshark captura o pacote OFPT_FLOW_MOD
        │                          │
        ▼                          ▼
  ping host1→host2 OK        confere a hierarquia Instructions→Actions
```

- **Entrada:** regra "porta 1 → porta 2".
- **Saída:** pacote binário `OFPT_FLOW_MOD` no Wireshark mostrando
  `FlowMod → Instructions → Apply_Actions → Action_Output`.
- **Validação:** fluxo instalado no Open vSwitch + conectividade (ping) entre
  hosts no Mininet.

---

## 7. Glossário rápido

| Termo | Significado |
|---|---|
| **SDN** | Redes Definidas por Software; separa controle e dados |
| **Plano de controle** | a inteligência (decide regras) — é o POX |
| **Plano de dados** | o encaminhamento bruto — é o switch |
| **OpenFlow** | protocolo binário entre controlador e switch |
| **DPID** | Datapath ID; identificador único de um switch |
| **FlowMod** (`OFPT_FLOW_MOD`) | mensagem que instala/modifica regra de fluxo |
| **Match** | critério que seleciona pacotes |
| **Action** (`OFPAT_*`) | operação sobre o pacote (ex.: `OUTPUT`) |
| **Instruction** (`OFPIT_*`) | **novidade do 1.1**; encapsula ações no pipeline |
| **APPLY_ACTIONS** | instrução que manda aplicar ações imediatamente |
| **Open vSwitch (OVS)** | switch virtual que fala OpenFlow |
| **Mininet** | emulador de redes que cria hosts/switches virtuais |
| **Wireshark** | analisador de pacotes; tem dissector de OpenFlow |
| **big-endian / `!`** | ordem de bytes da rede; usada em `struct.pack` |

---

## 8. Próximo passo

Com os conceitos firmes, os próximos comandos serão a implementação:
primeiro `libopenflow_11.py` (as estruturas + `pack()`), depois o componente
`ext/of11_instruction_poc.py`, e por fim a captura no Wireshark + teste no
Mininet/OVS.

Aguardando o próximo comando. 🧩
