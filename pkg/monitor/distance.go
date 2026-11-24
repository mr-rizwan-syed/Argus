package monitor

// osaWithin returns the optimal-string-alignment (Damerau-Levenshtein with adjacent transpositions) distance between a and b when it is at most
// max, and max+1 otherwise. Labels are at most 63 bytes, so the rows live on the stack.
func osaWithin(a, b string, max int) int {
	la, lb := len(a), len(b)
	if la > 64 || lb > 64 {
		return max + 1
	}
	if d := la - lb; d > max || -d > max {
		return max + 1
	}
	var r0, r1, r2 [66]int
	prev2, prev, cur := r0[:lb+1], r1[:lb+1], r2[:lb+1]
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		rowMin := cur[0]
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			v := prev[j] + 1
			if x := cur[j-1] + 1; x < v {
				v = x
			}
			if x := prev[j-1] + cost; x < v {
				v = x
			}
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				if x := prev2[j-2] + 1; x < v {
					v = x
				}
			}
			cur[j] = v
			if v < rowMin {
				rowMin = v
			}
		}
		if rowMin > max {
			return max + 1
		}
		prev2, prev, cur = prev, cur, prev2
	}
	if prev[lb] > max {
		return max + 1
	}
	return prev[lb]
}
