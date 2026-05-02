## Estrutura de Dados: O Estado (State)

No Mini-AES, os 16 bits de dados são organizados em uma matriz $2 \times 2$ de nibbles (cada nibble tem 4 bits). Seja o bloco de dados $B = [b_0, b_1, b_2, b_3 \dots b_{15}]$, a matriz de estado é:

|         | Coluna 0                 | Coluna 1                   |
|---------|--------------------------|----------------------------|
|Linha 0  |$s_{0,0}$​ (bits 0-3)|$s_{0,1}$​ (bits 8-11) |
|Linha 1  |$s_{1,0}$​ (bits 4-7)|$s_{1,1}$​ (bits 12-15)|

[Detalhes](./state.md)

---

## O Processo de Encriptação

O algoritmo é composto por um round inicial, um round principal e um round final. As etapas fundamentais são:

### 1. AddRoundKey (Adição de Chave): 

- É uma operação XOR ($\oplus$) simples entre o estado atual e a subchave gerada para aquele round.

$Estado = Estado \oplus Subchave$

### 2. NibbleSub (Substituição de Nibbles)

Cada nibble da matriz passa por uma S-Box (Caixa de Substituição). É uma função não-linear que troca o valor do nibble por outro pré-definido, garantindo a "confusão" dos dados.

### 3. ShiftRow (Deslocamento de Linhas)

Nesta etapa, as linhas da matriz de estado são deslocadas para a esquerda:

- A Linha 0 não muda.
- A Linha 1 sofre um deslocamento circular de 1 nibble para a esquerda.
- Resultado: $s_{1,0}$ e $s_{1,1}$ trocam de lugar.

### 3. MixColumn (Mistura de Colunas)

Esta é a parte mais complexa matematicamente. Cada coluna da matriz é multiplicada por uma matriz constante sobre o corpo finito $GF(2^4)$. Isso garante que cada bit do texto cifrado dependa de vários bits do texto original (difusão).
