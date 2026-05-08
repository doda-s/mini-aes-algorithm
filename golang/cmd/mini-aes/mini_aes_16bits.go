package main

// =============================================================================
// MINI AES DE 16 BITS - Implementação Educacional
// =============================================================================
// O AES (Advanced Encryption Standard) é um algoritmo de cifra simétrica por blocos.
// Esta versão "mini" usa blocos de 16 bits (em vez de 128 bits do AES real)
// para fins didáticos, mantendo a estrutura e os princípios do algoritmo original.
//
// ESTRUTURA DO MINI AES 16 BITS:
//   - Bloco: 16 bits (4 nibbles de 4 bits cada)
//   - Chave: 16 bits
//   - Rounds: 2 rounds completos + round inicial
//   - Estado: matriz 2x2 de nibbles (4 bits)
//
// Por que nibbles? O AES real opera com bytes (8 bits) em matrizes 4x4.
// Aqui usamos nibbles (4 bits) em matrizes 2x2 para simplificar a demonstração
// mantendo todos os passos conceituais.
// =============================================================================

import (
	"fmt"
	"strings"
)

// =============================================================================
// CAMPO FINITO GF(2^4)
// =============================================================================
// O AES opera em um campo finito (Galois Field). No AES real é GF(2^8).
// No Mini AES usamos GF(2^4) - números de 0 a 15.
//
// Por que campo finito?
// - Garante que operações sempre resultem em valores dentro do intervalo
// - Permite operações reversíveis (necessário para decriptação)
// - Propriedades algébricas que garantem difusão e confusão
//
// O polinômio irredutível usado: x^4 + x + 1 = 0b10011 = 0x13
// Este é o "módulo" das operações no campo GF(2^4)
// =============================================================================

// S-BOX: Tabela de substituição (SubNibbles)
// -----------------------------------------
// A S-Box é a principal fonte de "confusão" no AES.
// Cada nibble (0-15) é mapeado para outro nibble de forma não-linear.
// É construída usando inversão multiplicativa em GF(2^4) + transformação afim.
//
// Por que não-linear? Para resistir a ataques de criptoanálise linear e diferencial.
// Se a substituição fosse linear, um atacante poderia resolver equações lineares
// para descobrir a chave.
//
// Índice = nibble original, Valor = nibble substituído
var sBox = [16]uint8{
	0x9, 0x4, 0xA, 0xB, // 0x0..0x3
	0xD, 0x1, 0x8, 0x5, // 0x4..0x7
	0x6, 0x2, 0x0, 0x3, // 0x8..0xB
	0xC, 0xE, 0xF, 0x7, // 0xC..0xF
}

// S-BOX INVERSA: Para a decriptação (InvSubNibbles)
// A inversa é simplesmente o mapeamento ao contrário:
// se sBox[i] = j, então invSBox[j] = i
var invSBox = [16]uint8{
	0xA, 0x5, 0x9, 0xB, // 0x0..0x3
	0x1, 0x7, 0x8, 0xF, // 0x4..0x7
	0x6, 0x0, 0x2, 0x3, // 0x8..0xB
	0xC, 0x4, 0xD, 0xE, // 0xC..0xF
}

// =============================================================================
// REPRESENTAÇÃO DO ESTADO
// =============================================================================
// O estado é uma matriz 2x2 de nibbles (4 bits cada):
//
//   +----+----+
//   | s0 | s1 |
//   +----+----+
//   | s2 | s3 |
//   +----+----+
//
// Os 16 bits do bloco são distribuídos assim:
//   s0 = bits 15-12 (nibble mais significativo)
//   s1 = bits 11-8
//   s2 = bits 7-4
//   s3 = bits 3-0  (nibble menos significativo)
// =============================================================================

// State representa o estado interno do algoritmo: matriz 2x2 de nibbles
type State [2][2]uint8

// blockToState converte um bloco de 16 bits para a matriz de estado 2x2
func blockToState(block uint16) State {
	// Extrai cada nibble do bloco de 16 bits usando máscaras e deslocamentos
	return State{
		{uint8((block >> 12) & 0xF), uint8((block >> 8) & 0xF)},
		{uint8((block >> 4) & 0xF), uint8(block & 0xF)},
	}
}

// stateToBlock converte a matriz de estado 2x2 de volta para 16 bits
func stateToBlock(s State) uint16 {
	// Reconstrói o bloco combinando os nibbles nas posições corretas
	return (uint16(s[0][0]) << 12) | (uint16(s[0][1]) << 8) |
		(uint16(s[1][0]) << 4) | uint16(s[1][1])
}

// printState exibe o estado em formato de tabela para visualização
func printState(s State, label string) {
	fmt.Printf("  [%s]\n", label)
	fmt.Printf("  +----+----+\n")
	fmt.Printf("  | %X  | %X  |\n", s[0][0], s[0][1])
	fmt.Printf("  +----+----+\n")
	fmt.Printf("  | %X  | %X  |\n", s[1][0], s[1][1])
	fmt.Printf("  +----+----+\n")
}

// =============================================================================
// PASSO 1: AddRoundKey (XOR com a chave do round)
// =============================================================================
// A chave do round é combinada com o estado usando XOR (OU-exclusivo bit a bit).
//
// Por que XOR?
// - XOR é sua própria inversa: A XOR B XOR B = A
//   Isso torna a operação facilmente reversível na decriptação
// - XOR é uma operação de campo (Group operation em GF(2))
// - Sem o AddRoundKey, os outros passos seriam independentes da chave,
//   tornando o ciframento inútil como criptografia
//
// É o único passo que "mistura" a chave com os dados.
// =============================================================================

func addRoundKey(s State, key uint16) State {
	// Converte a chave para estado e aplica XOR nibble por nibble
	k := blockToState(key)
	return State{
		{s[0][0] ^ k[0][0], s[0][1] ^ k[0][1]},
		{s[1][0] ^ k[1][0], s[1][1] ^ k[1][1]},
	}
}

// =============================================================================
// PASSO 2: SubNibbles (Substituição de nibbles via S-Box)
// =============================================================================
// Cada nibble do estado é substituído pelo valor correspondente na S-Box.
//
// Por que substituir?
// - Introduz NÃO-LINEARIDADE no algoritmo
// - "Confusão": torna a relação entre chave e texto cifrado complexa
// - Sem este passo, todo o algoritmo seria linear e facilmente quebrável
//   por álgebra linear simples
//
// A S-Box foi construída para maximizar a "não-linearidade" e resistência
// a ataques de criptoanálise diferencial e linear.
// =============================================================================

func subNibbles(s State) State {
	return State{
		{sBox[s[0][0]], sBox[s[0][1]]},
		{sBox[s[1][0]], sBox[s[1][1]]},
	}
}

// invSubNibbles é o inverso: usa a S-Box inversa para decriptação
func invSubNibbles(s State) State {
	return State{
		{invSBox[s[0][0]], invSBox[s[0][1]]},
		{invSBox[s[1][0]], invSBox[s[1][1]]},
	}
}

// =============================================================================
// PASSO 3: ShiftRows (Rotação das linhas)
// =============================================================================
// As linhas da matriz de estado são rotacionadas ciclicamente para a esquerda.
//
// No Mini AES 2x2:
//   - Linha 0: não é rotacionada (shift de 0)
//   - Linha 1: rotacionada 1 posição para a esquerda
//
// Estado antes:        Estado depois:
//   +----+----+          +----+----+
//   | s0 | s1 |    →     | s0 | s1 |  (linha 0: sem mudança)
//   +----+----+          +----+----+
//   | s2 | s3 |    →     | s3 | s2 |  (linha 1: swap!)
//   +----+----+          +----+----+
//
// Por que rotacionar?
// - "Difusão": garante que nibbles de diferentes colunas se misturem
// - Sem este passo, cada coluna seria cifrada independentemente
//   (seria equivalente a 4 cifras independentes, muito mais fraca)
// - No AES real (4x4), os shifts são 0,1,2,3 posições por linha
// =============================================================================

func shiftRows(s State) State {
	return State{
		{s[0][0], s[0][1]}, // Linha 0: mantém [s0, s1]
		{s[1][1], s[1][0]}, // Linha 1: troca [s2, s3] → [s3, s2]
	}
}

// invShiftRows é idêntico ao shiftRows neste caso (trocar 2 elementos é auto-inverso)
// No AES real, a inversa seria rotação para a direita
func invShiftRows(s State) State {
	return shiftRows(s) // Para matriz 2x2, trocar é auto-inverso
}

// =============================================================================
// PASSO 4: MixColumns (Mistura das colunas em GF(2^4))
// =============================================================================
// Cada coluna da matriz é tratada como um polinômio sobre GF(2^4) e
// multiplicada por uma matriz de mistura fixa.
//
// A matriz de mistura usada:
//   [1  4]   (representada em GF(2^4))
//   [4  1]
//
// Operação para cada coluna [a, b]:
//   nova_col = [1*a XOR 4*b, 4*a XOR 1*b]
//
// Por que misturar colunas?
// - Provê "difusão" vertical: cada byte de saída depende de todos os bytes da coluna
// - Garante que a mudança de 1 bit na entrada afete múltiplos bits na saída
// - Sem MixColumns, o algoritmo seria muito mais fraco
//
// A multiplicação por 4 em GF(2^4) é uma operação especial que mantém
// os resultados dentro do campo (0-15).
// =============================================================================

// mulGF multiplica dois números em GF(2^4) com polinômio x^4 + x + 1 (0x13)
// Esta é a operação matemática que permite que tudo funcione no campo finito
func mulGF(a, b uint8) uint8 {
	// Algoritmo: multiplicação "carry-less" com redução modular
	// Semelhante à multiplicação binária, mas sem carry (apenas XOR)
	var result uint8 = 0
	for i := 0; i < 4; i++ {
		if b&1 != 0 {
			result ^= a // Se o bit menos significativo de b é 1, XOR com a
		}
		// Verifica se haverá overflow (bit 3 de a está setado)
		hiBitSet := a&0x8 != 0
		a <<= 1  // Multiplica a por x (deslocamento à esquerda)
		a &= 0xF // Mantém apenas 4 bits
		if hiBitSet {
			a ^= 0x3 // Redução: x^4 = x + 1, então XOR com 0x3 (os coef. de x+1)
		}
		b >>= 1 // Próximo bit de b
	}
	return result
}

func mixColumns(s State) State {
	// Coluna 0: s[0][0] e s[1][0]
	// Coluna 1: s[0][1] e s[1][1]
	//
	// Para coluna [a, b]:
	//   novo_a = (1*a) XOR (4*b) = a XOR mulGF(4,b)
	//   novo_b = (4*a) XOR (1*b) = mulGF(4,a) XOR b
	return State{
		{
			mulGF(1, s[0][0]) ^ mulGF(4, s[1][0]), // nova posição [0][0]
			mulGF(1, s[0][1]) ^ mulGF(4, s[1][1]), // nova posição [0][1]
		},
		{
			mulGF(4, s[0][0]) ^ mulGF(1, s[1][0]), // nova posição [1][0]
			mulGF(4, s[0][1]) ^ mulGF(1, s[1][1]), // nova posição [1][1]
		},
	}
}

// invMixColumns: a matriz inversa de mistura
// Para inverter MixColumns, precisamos da matriz inversa de [[1,4],[4,1]] em GF(2^4).
//
// Cálculo da inversa de [[1,4],[4,1]]:
//
//	det = 1*1 XOR mulGF(4,4) = 1 XOR 3 = 2 (em GF(2^4))
//	det^{-1} = 9  (pois mulGF(2,9) = 1 em GF(2^4))
//	M^{-1} = det^{-1} * [[1,4],[4,1]] = [[9*1, 9*4],[9*4, 9*1]] = [[9,2],[2,9]]
//
// Portanto a matriz inversa é [[9,2],[2,9]] em GF(2^4).
// Para cada coluna [a, b]:
//
//	novo_a = mulGF(9,a) XOR mulGF(2,b)
//	novo_b = mulGF(2,a) XOR mulGF(9,b)
func invMixColumns(s State) State {
	return State{
		{
			mulGF(9, s[0][0]) ^ mulGF(2, s[1][0]),
			mulGF(9, s[0][1]) ^ mulGF(2, s[1][1]),
		},
		{
			mulGF(2, s[0][0]) ^ mulGF(9, s[1][0]),
			mulGF(2, s[0][1]) ^ mulGF(9, s[1][1]),
		},
	}
}

// =============================================================================
// EXPANSÃO DE CHAVE (Key Schedule)
// =============================================================================
// A partir de uma chave inicial de 16 bits, geramos sub-chaves para cada round.
//
// Por que expandir a chave?
// - Cada round precisa de uma chave diferente para ser seguro
// - Se usássemos a mesma chave em todos os `s, haveria padrões exploráveis
// - A expansão garante que uma pequena mudança na chave original
//   produza sub-chaves muito diferentes (efeito avalanche na chave)
//
// Constantes de Round (RCON):
// São constantes derivadas de potências de 2 em GF(2^4).
// Evitam simetria na expansão de chave (sem RCON, chaves simétricas
// produziriam sub-chaves idênticas, vulnerabilidade grave).
//
// Para Mini AES: geramos 3 sub-chaves (round 0, 1 e 2)
// =============================================================================

// rcon são as constantes de round em GF(2^4): 2^0=1, 2^1=2, 2^2=4
var rcon = [3]uint8{0x1, 0x2, 0x4}

// TODO: ENTENDER MELHOR ESTA PARTE
// keyExpansion gera as 3 sub-chaves a partir da chave original
func keyExpansion(key uint16) [3]uint16 {
	keys := [3]uint16{}
	keys[0] = key // A primeira sub-chave é a própria chave

	// Extrai os dois bytes da chave atual
	// w0 = byte mais significativo, w1 = byte menos significativo
	w0 := uint8(key >> 8)
	w1 := uint8(key & 0xFF)

	// Gera as próximas sub-chaves usando uma função de mistura
	for i := 1; i < 3; i++ {
		// g(w1): função de mistura aplicada ao último byte
		//   1. Rotaciona os nibbles: [a, b] → [b, a]
		//      (no AES real, seria uma rotação de bytes)
		g_hi := w1 & 0xF        // nibble baixo de w1
		g_lo := (w1 >> 4) & 0xF // nibble alto de w1

		//   2. Aplica S-Box em cada nibble
		g_hi = sBox[g_hi]
		g_lo = sBox[g_lo]

		//   3. XOR com constante de round (RCON) no nibble alto
		//      RCON evita simetrias e fraquezas na expansão
		g := (g_hi << 4) | g_lo
		g ^= (rcon[i-1] << 4) // XOR do RCON apenas no nibble mais significativo

		// Novas palavras: XOR das palavras anteriores com g
		w0 = w0 ^ g
		w1 = w1 ^ w0

		// Combina os bytes para formar a próxima sub-chave de 16 bits
		keys[i] = (uint16(w0) << 8) | uint16(w1)
	}

	return keys
}

// =============================================================================
// ENCRIPTAÇÃO COMPLETA
// =============================================================================
// O Mini AES executa estes rounds:
//
//   Round 0 (inicial):  AddRoundKey(key0)
//   Round 1 (completo): SubNibbles → ShiftRows → MixColumns → AddRoundKey(key1)
//   Round 2 (final):    SubNibbles → ShiftRows → AddRoundKey(key2)
//                       (sem MixColumns no último round - padrão do AES)
//
// Por que omitir MixColumns no último round?
// - Razão histórica e de implementação: torna a decriptação mais simples
// - Não prejudica a segurança (o AddRoundKey final já provê a mistura necessária)
// =============================================================================

func encrypt(plaintext, key uint16, verbose bool) uint16 {
	// Gera as 3 sub-chaves para os 3 rounds
	keys := keyExpansion(key)

	// TODO: REMOVÍVEL
	if verbose {
		fmt.Printf("\n%s\n", strings.Repeat("=", 60))
		fmt.Println("  PROCESSO DE ENCRIPTAÇÃO")
		fmt.Printf("%s\n", strings.Repeat("=", 60))
		fmt.Printf("  Texto plano:  0x%04X (%016b)\n", plaintext, plaintext)
		fmt.Printf("  Chave:        0x%04X (%016b)\n", key, key)
		fmt.Printf("  Sub-chaves geradas:\n")
		for i, k := range keys {
			fmt.Printf("    K%d = 0x%04X\n", i, k)
		}
	}

	// Converte o bloco para a representação matricial
	// TODO: BUSCAR EXPLICACAO MELHOR PARA ESTE TRECHO
	state := blockToState(plaintext)
	if verbose {
		fmt.Println("\n--- Estado Inicial ---")
		printState(state, "Texto Plano")
	}

	state = addRoundKey(state, keys[0])
	if verbose {
		fmt.Println("\n--- Round 0: AddRoundKey(K0) ---")
		fmt.Printf("  XOR com K0 = 0x%04X\n", keys[0])
		printState(state, "Após AddRoundKey(K0)")
	}

	totalRounds := 2

	for i := 0; i < totalRounds; i++ {
		state = subNibbles(state)
		if verbose {
			printState(state, "Após SubNibbles")
		}

		state = shiftRows(state)
		if verbose {
			printState(state, "Após ShiftRows")
		}

		// Não executar no último round
		if i < totalRounds-1 {
			state = mixColumns(state)
			if verbose {
				printState(state, "Após MixColumns")
			}
		}

		state = addRoundKey(state, keys[i+1])
		if verbose {
			fmt.Printf("  XOR com K%d = 0x%04X\n", i+1, keys[i+1])
			printState(state, "Após AddRoundKey")
		}
	}

	// Converte o estado final de volta para 16 bits
	ciphertext := stateToBlock(state)

	if verbose {
		fmt.Printf("\n%s\n", strings.Repeat("=", 60))
		fmt.Printf("  TEXTO CIFRADO: 0x%04X (%016b)\n", ciphertext, ciphertext)
		fmt.Printf("%s\n", strings.Repeat("=", 60))
	}

	return ciphertext
}

// =============================================================================
// DECRIPTAÇÃO COMPLETA
// =============================================================================
// A decriptação executa os passos na ordem INVERSA com operações INVERSAS:
//
//   Round 2 (inverso):  AddRoundKey(key2) → InvShiftRows → InvSubNibbles
//   Round 1 (inverso):  AddRoundKey(key1) → InvMixColumns → InvShiftRows → InvSubNibbles
//   Round 0 (inverso):  AddRoundKey(key0)
//
// Propriedade fundamental: cada operação é projetada para ter uma inversa exata.
// AddRoundKey é auto-inversa (XOR com a mesma chave desfaz a operação).
// =============================================================================

func decrypt(ciphertext, key uint16, verbose bool) uint16 {
	// Regenera as mesmas sub-chaves usadas na encriptação
	keys := keyExpansion(key)

	if verbose {
		fmt.Printf("\n%s\n", strings.Repeat("=", 60))
		fmt.Println("  PROCESSO DE DECRIPTAÇÃO")
		fmt.Printf("%s\n", strings.Repeat("=", 60))
		fmt.Printf("  Texto cifrado: 0x%04X (%016b)\n", ciphertext, ciphertext)
		fmt.Printf("  Chave:         0x%04X (%016b)\n", key, key)
	}

	state := blockToState(ciphertext)
	if verbose {
		fmt.Println("\n--- Estado Inicial (Texto Cifrado) ---")
		printState(state, "Texto Cifrado")
	}

	// -------------------------------------------------------------------------
	// INVERSO DO ROUND 2: AddRoundKey → InvShiftRows → InvSubNibbles
	// Aplicamos as operações inversas na ordem inversa
	// -------------------------------------------------------------------------

	for round := 2; round >= 1; round-- {

		if verbose {
			fmt.Printf("\n--- Inverso do Round %d ---\n", round)
		}

		// AddRoundKey
		state = addRoundKey(state, keys[round])
		if verbose {
			printState(state, fmt.Sprintf("Após AddRoundKey(K%d)", round))
		}

		// InvMixColumns (não acontece no último round)
		if round != 2 {
			state = invMixColumns(state)
			if verbose {
				printState(state, "Após InvMixColumns")
			}
		}

		// InvShiftRows
		state = invShiftRows(state)
		if verbose {
			printState(state, "Após InvShiftRows")
		}

		// InvSubNibbles
		state = invSubNibbles(state)
		if verbose {
			printState(state, "Após InvSubNibbles")
		}
	}

	// -------------------------------------------------------------------------
	// INVERSO DO ROUND 0: Apenas AddRoundKey com a chave original
	// -------------------------------------------------------------------------
	if verbose {
		fmt.Println("\n--- Inverso do Round 0 ---")
	}

	state = addRoundKey(state, keys[0])
	if verbose {
		printState(state, "Após AddRoundKey(K0)")
	}

	plaintext := stateToBlock(state)

	if verbose {
		fmt.Printf("\n%s\n", strings.Repeat("=", 60))
		fmt.Printf("  TEXTO RECUPERADO: 0x%04X (%016b)\n", plaintext, plaintext)
		fmt.Printf("%s\n", strings.Repeat("=", 60))
	}

	return plaintext
}

// =============================================================================
// ATAQUE DE FORÇA BRUTA (Quebra de Chave)
// =============================================================================
// Para Mini AES de 16 bits, o espaço de chaves é 2^16 = 65.536 possibilidades.
// Um ataque de força bruta testa todas as chaves possíveis.
//
// Por que isso é viável aqui mas não no AES real?
// - Mini AES 16 bits: 2^16 = 65.536 chaves → fração de segundo
// - AES-128 real: 2^128 ≈ 340 undecilhões de chaves → impossível na prática
//
// Este ataque ilustra por que o tamanho da chave é crítico para a segurança.
// =============================================================================

func bruteForce(plaintext, ciphertext uint16) (uint16, bool, int) {
	attempts := 0
	// Testa todas as 65.536 chaves possíveis (0x0000 a 0xFFFF)
	for key := uint16(0); key <= 0xFFFF; key++ {
		attempts++
		// Encripta com esta chave e verifica se bate com o texto cifrado
		if encrypt(plaintext, key, false) == ciphertext {
			return key, true, attempts // Chave encontrada!
		}
	}
	return 0, false, attempts
}

// =============================================================================
// FUNÇÃO PRINCIPAL: Demonstração completa
// =============================================================================

func main() {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║          MINI AES DE 16 BITS - Trabalho Acadêmico        ║")
	fmt.Println("║     Implementação Educacional com Passos Explicados      ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")

	// Valores de exemplo
	plaintext := uint16(0xABEC) // Texto plano: 0001 0010 0011 0100
	key := uint16(0xABCD)       // Chave:       1010 1011 1100 1101

	// =========================================================================
	// DEMONSTRAÇÃO DE ENCRIPTAÇÃO
	// =========================================================================
	ciphertext := encrypt(plaintext, key, true)

	// =========================================================================
	// DEMONSTRAÇÃO DE DECRIPTAÇÃO
	// =========================================================================
	recovered := decrypt(ciphertext, key, true)

	// =========================================================================
	// VERIFICAÇÃO
	// =========================================================================
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║                    VERIFICAÇÃO FINAL                     ║")
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Texto Plano Original:  0x%04X                           ║\n", plaintext)
	fmt.Printf("║  Chave Usada:           0x%04X                           ║\n", key)
	fmt.Printf("║  Texto Cifrado:         0x%04X                           ║\n", ciphertext)
	fmt.Printf("║  Texto Recuperado:      0x%04X                           ║\n", recovered)
	if plaintext == recovered {
		fmt.Println("║  Status: ✓ CORRETO - Encriptação/Decriptação funcionou!  ║")
	} else {
		fmt.Println("║  Status: ✗ ERRO - Algo deu errado!                       ║")
	}
	fmt.Println("╚══════════════════════════════════════════════════════════╝")

	// =========================================================================
	// DEMONSTRAÇÃO DE FORÇA BRUTA
	// =========================================================================
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║            ATAQUE DE FORÇA BRUTA (Quebra de Chave)       ║")
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Procurando chave para: texto=0x%04X → cifrado=0x%04X  ║\n", plaintext, ciphertext)
	fmt.Println("║  Testando todas as 65.536 chaves possíveis (2^16)...     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")

	foundKey, found, attempts := bruteForce(plaintext, ciphertext)
	if found {
		fmt.Printf("\n  ✓ CHAVE ENCONTRADA após %d tentativas!\n", attempts)
		fmt.Printf("  Chave: 0x%04X (coincide com a chave original: 0x%04X)\n", foundKey, key)
		fmt.Printf("\n  → No AES-128 real seriam 2^128 tentativas.\n")
		fmt.Printf("    Isso levaria bilhões de anos mesmo com supercomputadores!\n")
	}

	// =========================================================================
	// TESTE COM MÚLTIPLOS VALORES
	// =========================================================================
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║               TESTES COM MÚLTIPLOS VALORES                ║")
	fmt.Println("╠════════════════╦══════════╦══════════╦════════════════╦═══╣")
	fmt.Println("║  Texto Plano   ║  Chave   ║  Cifrado ║  Recuperado    ║OK ║")
	fmt.Println("╠════════════════╬══════════╬══════════╬════════════════╬═══╣")

	testCases := [][2]uint16{
		{0x1234, 0xABCD},
		{0x0000, 0xFFFF},
		{0xFFFF, 0x0000},
		{0xDEAD, 0xBEEF},
		{0x1111, 0x2222},
	}

	for _, tc := range testCases {
		pt, k := tc[0], tc[1]
		ct := encrypt(pt, k, false)
		rec := decrypt(ct, k, false)
		status := "✓"
		if pt != rec {
			status = "✗"
		}
		fmt.Printf("║  0x%04X        ║  0x%04X  ║  0x%04X  ║  0x%04X        ║ %s ║\n",
			pt, k, ct, rec, status)
	}
	fmt.Println("╚════════════════╩══════════╩══════════╩════════════════╩═══╝")
}
