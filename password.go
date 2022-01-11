package passwordchecker

import (
	"fmt"
	"strings"
	"sync"
	"unicode"
)

type rules struct {
	specialCharacters []string
	_minChar,
	needNumberCount,
	needLowerCharactersCount,
	needUpperCharactersCount,
	needSpecialCharactersCount uint8
	_maxChar uint
}

func (p *Password) rules() rules {
	p.rulesLock.RLock()
	defer p.rulesLock.RUnlock()
	return p._rules
}

func (p *Password) setRules(r rules) {
	p.rulesLock.Lock()
	p._rules = r
	p.rulesLock.Unlock()
}

type Password struct {
	rulesLock sync.RWMutex
	_rules    rules
}

/*
New build a Password checker
*/
func New(minChar uint8, maxChar uint,
	needNumberCount, needLowerCharactersCount, needUpperCharactersCount, needSpecialCharactersCount uint8,
	specialCharacters ...string) *Password {

	pass := &Password{}

	pass.buildRules(minChar, maxChar,
		needNumberCount, needLowerCharactersCount, needUpperCharactersCount, needSpecialCharactersCount,
		specialCharacters)

	return pass
}

//ChangeRules change the rules of passwords
func (p *Password) ChangeRules(minChar uint8, maxChar uint,
	needNumberCount, needLowerCharactersCount, needUpperCharactersCount, needSpecialCharactersCount uint8,
	specialCharacters ...string) {

	p.buildRules(minChar, maxChar,
		needNumberCount, needLowerCharactersCount, needUpperCharactersCount, needSpecialCharactersCount,
		specialCharacters)

}

func (p *Password) buildRules(minChar uint8, maxChar uint,
	needNumberCount, needLowerCharactersCount, needUpperCharactersCount, needSpecialCharactersCount uint8,
	specialCharacters []string) {
	if len(specialCharacters) == 0 {
		specialCharacters = []string{"!", "@", "#", "$", "%", "&", "*", "-", "_", "=", "+", "^", "~", "?", ":"}
	}

	totalNeed := uint(needLowerCharactersCount + needUpperCharactersCount + needSpecialCharactersCount + needNumberCount)

	if totalNeed > maxChar {
		maxChar = totalNeed
	}

	rules := p.rules()
	rules.specialCharacters = specialCharacters
	rules._minChar = minChar
	rules._maxChar = maxChar
	rules.needNumberCount = needNumberCount
	rules.needLowerCharactersCount = needLowerCharactersCount
	rules.needUpperCharactersCount = needUpperCharactersCount
	rules.needSpecialCharactersCount = needSpecialCharactersCount
	p.setRules(rules)
}

func (p *Password) countSpecialCharactersOfString(pass string) (total int) {
	for _, special := range p.rules().specialCharacters {
		if special != "" {
			total += strings.Count(pass, special)
		}
	}

	return
}

func (p *Password) haveSpecialCharacters(pass string) bool {
	if p.rules().needSpecialCharactersCount > 0 {
		return p.countSpecialCharactersOfString(pass) >= int(p.rules().needSpecialCharactersCount)
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
	if p.rules().needLowerCharactersCount > 0 {
		return countLowerCharactersOfString(pass) >= int(p.rules().needLowerCharactersCount)
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
	if p.rules().needUpperCharactersCount > 0 {
		return countUpperCharactersOfString(pass) >= int(p.rules().needUpperCharactersCount)
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
	if p.rules().needNumberCount > 0 {
		return countNumbersOfString(pass) >= int(p.rules().needNumberCount)
	}

	return true
}

func (p *Password) minChar(pass string) bool {
	return len(pass) >= int(p.rules()._minChar)
}

func (p *Password) maxChar(pass string) bool {
	if p.rules()._maxChar > 0 {
		return len(pass) <= int(p.rules()._maxChar)
	}

	return true
}

func (p *Password) Check(pass string) error {
	if !p.minChar(pass) {
		return fmt.Errorf("senha precisa ter no mínimo %d caracteres", p.rules()._minChar)
	}

	if !p.maxChar(pass) {
		return fmt.Errorf("senha precisa ter no máximo %d caracteres", p.rules()._maxChar)
	}

	if !p.haveNumberChar(pass) {
		if p.rules().needNumberCount > 1 {
			return fmt.Errorf("senha precisa ter no mínimo %d números", p.rules().needNumberCount)
		}
		return fmt.Errorf("senha precisa ter no mínimo 1 número")
	}

	if !p.haveUpperCharacters(pass) {
		if p.rules().needUpperCharactersCount > 1 {
			return fmt.Errorf("senha precisa ter no mínimo %d caracteres maiúsculos", p.rules().needUpperCharactersCount)
		}
		return fmt.Errorf("senha precisa ter no mínimo 1 caracter maiúsculo")
	}

	if !p.haveLowerCharacters(pass) {
		if p.rules().needLowerCharactersCount > 1 {
			return fmt.Errorf("senha precisa ter no mínimo %d caracteres minúsculos", p.rules().needLowerCharactersCount)
		}
		return fmt.Errorf("senha precisa ter no mínimo 1 caracter minúsculo")
	}

	if !p.haveSpecialCharacters(pass) {
		if p.rules().needSpecialCharactersCount > 1 {
			return fmt.Errorf("senha precisa ter no mínimo %d caracteres especiais: %q", p.rules().needSpecialCharactersCount, p.rules().specialCharacters)
		}
		return fmt.Errorf("senha precisa ter no mínimo 1 caracter especial: %q", p.rules().specialCharacters)
	}

	return nil
}
