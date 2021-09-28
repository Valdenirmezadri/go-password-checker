package passwordchecker

import (
	"fmt"
	"strings"
	"unicode"
)

type Password struct {
	specialCharacters                                                                       []string
	minChar, maxChar, needNumberCount, needUpperCharactersCount, needSpecialCharactersCount uint8
}

/*
New build a Password checker
*/
func New(minChar, maxChar uint8,
	needNumberCount uint8, needUpperCharactersCount uint8, needSpecialCharactersCount uint8, specialCharacters ...string) *Password {

	if len(specialCharacters) == 0 {
		specialCharacters = []string{"!", "@", "#", "$", "%", "&", "*", "-", "_", "=", "+", "^", "~", "?", ":"}
	}

	totalNeed := needUpperCharactersCount + needSpecialCharactersCount + needNumberCount

	if totalNeed > maxChar {
		maxChar = maxChar + totalNeed
	}

	return &Password{
		specialCharacters:          specialCharacters,
		minChar:                    minChar,
		maxChar:                    maxChar,
		needNumberCount:            needNumberCount,
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

func (p *Password) MinChar(pass string) bool {
	return len(pass) >= int(p.minChar)
}

func (p *Password) MaxChar(pass string) bool {
	if p.maxChar > 0 {
		return len(pass) <= int(p.maxChar)
	}

	return true
}

func (p *Password) Check(pass string) error {
	if !p.MinChar(pass) {
		return fmt.Errorf("senha precisa ter no mínimo %d caracteres", p.minChar)
	}

	if !p.MaxChar(pass) {
		return fmt.Errorf("senha precisa ter no máximo %d caracteres", p.maxChar)
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

	if !p.haveSpecialCharacters(pass) {
		if p.needSpecialCharactersCount > 1 {
			return fmt.Errorf("senha precisa ter no mínimo %d caracteres especiais: %q", p.needSpecialCharactersCount, p.specialCharacters)
		}
		return fmt.Errorf("senha precisa ter no mínimo 1 caracter especial: %q", p.specialCharacters)
	}

	return nil
}
