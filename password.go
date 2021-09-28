package passwordchecker

import (
	"fmt"
	"strings"
	"unicode"
)

type Password struct {
	specialCharacters []string
	_minChar,
	needNumberCount,
	needLowerCharactersCount,
	needUpperCharactersCount,
	needSpecialCharactersCount uint8
	_maxChar uint
}

/*
New build a Password checker
*/
func New(minChar uint8, maxChar uint,
	needNumberCount, needLowerCharactersCount, needUpperCharactersCount, needSpecialCharactersCount uint8,
	specialCharacters ...string) *Password {

	if len(specialCharacters) == 0 {
		specialCharacters = []string{"!", "@", "#", "$", "%", "&", "*", "-", "_", "=", "+", "^", "~", "?", ":"}
	}

	totalNeed := uint(needLowerCharactersCount + needUpperCharactersCount + needSpecialCharactersCount + needNumberCount)

	if totalNeed > maxChar {
		maxChar = totalNeed
	}

	return &Password{
		specialCharacters:          specialCharacters,
		_minChar:                   minChar,
		_maxChar:                   maxChar,
		needNumberCount:            needNumberCount,
		needLowerCharactersCount:   needLowerCharactersCount,
		needUpperCharactersCount:   needUpperCharactersCount,
		needSpecialCharactersCount: needSpecialCharactersCount,
	}
}

func (p *Password) countSpecialCharactersOfString(pass string) (total int) {
	for _, special := range p.specialCharacters {
		if special != "" && strings.Contains(pass, special) {
			total += 1
		}
	}

	return
}

func (p *Password) haveSpecialCharacters(pass string) bool {
	if p.needSpecialCharactersCount > 0 {
		return p.countSpecialCharactersOfString(pass) >= int(p.needSpecialCharactersCount)
	}

	return true
}

func countLowerCharactersOfString(pass string) (total int) {
	for _, char := range pass {
		if unicode.IsLower(char) {
			total += 1
		}
	}
	return
}

func (p *Password) haveLowerCharacters(pass string) bool {
	if p.needLowerCharactersCount > 0 {
		return countLowerCharactersOfString(pass) >= int(p.needLowerCharactersCount)
	}

	return true
}

func countUpperCharactersOfString(pass string) (total int) {
	for _, char := range pass {
		if unicode.IsUpper(char) {
			total += 1
		}
	}
	return
}

func (p *Password) haveUpperCharacters(pass string) bool {
	if p.needUpperCharactersCount > 0 {
		return countUpperCharactersOfString(pass) >= int(p.needUpperCharactersCount)
	}

	return true
}

func countNumbersOfString(pass string) (total int) {
	for _, char := range pass {
		if unicode.IsNumber(char) {
			total += 1
		}
	}
	return
}

func (p *Password) haveNumberChar(pass string) bool {
	if p.needNumberCount > 0 {
		return countNumbersOfString(pass) >= int(p.needNumberCount)
	}

	return true
}

func (p *Password) minChar(pass string) bool {
	return len(pass) >= int(p._minChar)
}

func (p *Password) maxChar(pass string) bool {
	if p._maxChar > 0 {
		return len(pass) <= int(p._maxChar)
	}

	return true
}

func (p *Password) Check(pass string) error {
	if !p.minChar(pass) {
		return fmt.Errorf("senha precisa ter no mínimo %d caracteres", p._minChar)
	}

	if !p.maxChar(pass) {
		return fmt.Errorf("senha precisa ter no máximo %d caracteres", p._maxChar)
	}

	if !p.haveNumberChar(pass) {
		if p.needNumberCount > 1 {
			return fmt.Errorf("senha precisa ter no mínimo %d números", p.needNumberCount)
		}
		return fmt.Errorf("senha precisa ter no mínimo 1 número")
	}

	if !p.haveUpperCharacters(pass) {
		if p.needUpperCharactersCount > 1 {
			return fmt.Errorf("senha precisa ter no mínimo %d caracteres maiúsculos", p.needUpperCharactersCount)
		}
		return fmt.Errorf("senha precisa ter no mínimo 1 caracter maiúsculo")
	}

	if !p.haveLowerCharacters(pass) {
		if p.needLowerCharactersCount > 1 {
			return fmt.Errorf("senha precisa ter no mínimo %d caracteres minúsculos", p.needLowerCharactersCount)
		}
		return fmt.Errorf("senha precisa ter no mínimo 1 caracter minúsculo")
	}

	if !p.haveSpecialCharacters(pass) {
		if p.needSpecialCharactersCount > 1 {
			return fmt.Errorf("senha precisa ter no mínimo %d caracteres especiais: %q", p.needSpecialCharactersCount, p.specialCharacters)
		}
		return fmt.Errorf("senha precisa ter no mínimo 1 caracter especial: %q", p.specialCharacters)
	}

	return nil
}
