# State

A forma como organizamos os dados é crucial, pois todas as operações subsequentes (troca de nibbles, rotação de linhas e mistura de colunas) dependem da posição geométrica desses bits.

Para entender o State (Estado), imagine que você tem uma entrada de 16 bits. O algoritmo não olha para eles como uma linha única, mas sim como uma matriz quadrada.

---

## 1. Do Fluxo de Bits para a Matriz

Primeiro, dividimos os 16 bits em 4 nibbles (grupos de 4 bits cada).

Se a sua entrada for o valor hexadecimal 0x4A6F, a representação binária seria:0100 ($n_0$) | 1010 ($n_1$) | 0110 ($n_2$) | 1111 ($n_3$)

No Mini-AES, o preenchimento da matriz é feito por colunas (order-major column), seguindo este esquema:

|       |Coluna 0|Coluna 1|
|-------|--------|--------|
|Linha 0|Nibble 0|Nibble 2|
|Linha 1|Nibble 1|Nibble 3|

---

## 2. Por que usar uma Matriz?

Essa estrutura não é estética; ela serve para que o algoritmo execute dois tipos de difusão:

- **Vertical**: O MixColumn opera nas colunas.
- **Horizontal**: O ShiftRow opera nas linhas.

Ao alternar entre essas operações, um único bit alterado na entrada "espalha" sua influência por toda a matriz muito rapidamente.

---

## 3. Representação Matemática

Cada célula da matriz $s_{i,j}$ é tratada como um elemento de um Corpo de Galois ($GF(2^4)$). Isso significa que, embora o valor seja um nibble (de 0 a 15 em decimal), as operações matemáticas dentro da matriz seguem regras de álgebra linear específicas para garantir que os resultados sempre caibam em 4 bits.

No seu código, você pode representar isso como uma matriz bidimensional simples ou até um array linear, desde que a lógica de acesso respeite as posições:

- Estado[0][0] = bits 0-3
- Estado[1][0] = bits 4-7
- Estado[0][1] = bits 8-11
- Estado[1][1] = bits 12-15
