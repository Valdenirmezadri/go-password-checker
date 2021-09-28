package passwordchecker

import (
	"testing"
)

func Test_countNumbersOfString(t *testing.T) {
	type args struct {
		pass string
	}
	tests := []struct {
		name      string
		args      args
		wantTotal int
	}{
		{name: "want five", args: args{pass: "a3d5f6g7h8"}, wantTotal: 5},
		{name: "want zero", args: args{pass: "adf!^ fd gh"}, wantTotal: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotTotal := countNumbersOfString(tt.args.pass); gotTotal != tt.wantTotal {
				t.Errorf("countNumbersOfString() = %v, want %v", gotTotal, tt.wantTotal)
			}
		})
	}
}

func TestPassword_countSpecialCharactersOfString(t *testing.T) {
	specials := []string{"!", "@", "#", "$", "%", "&", "*", "-", "_", "=", "+", "^", "~", "?", ":"}
	type fields struct {
		specialCharacters          []string
		minChar                    uint8
		maxChar                    uint
		needNumberCount            uint8
		needUpperCharactersCount   uint8
		needSpecialCharactersCount uint8
	}
	type args struct {
		pass string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantTotal int
	}{
		{name: "have 5", fields: fields{specialCharacters: specials},
			args: args{pass: "ae$%&234gfdgy@*"}, wantTotal: 5},
		{name: "have 0", fields: fields{specialCharacters: specials},
			args: args{pass: "ae234gfdgy"}, wantTotal: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Password{
				specialCharacters:          tt.fields.specialCharacters,
				minChar:                    tt.fields.minChar,
				maxChar:                    tt.fields.maxChar,
				needNumberCount:            tt.fields.needNumberCount,
				needUpperCharactersCount:   tt.fields.needUpperCharactersCount,
				needSpecialCharactersCount: tt.fields.needSpecialCharactersCount,
			}
			if gotTotal := p.countSpecialCharactersOfString(tt.args.pass); gotTotal != tt.wantTotal {
				t.Errorf("Password.countSpecialCharactersOfString() = %v, want %v", gotTotal, tt.wantTotal)
			}
		})
	}
}

func TestPassword_haveSpecialCharacters(t *testing.T) {
	specials := []string{"!", "@", "#", "$", "%", "&", "*", "-", "_", "=", "+", "^", "~", "?", ":"}
	type fields struct {
		specialCharacters          []string
		minChar                    uint8
		maxChar                    uint
		needNumberCount            uint8
		needUpperCharactersCount   uint8
		needSpecialCharactersCount uint8
	}
	type args struct {
		pass string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{name: "true", fields: fields{needSpecialCharactersCount: 1, specialCharacters: specials}, args: args{pass: "asf%efd"}, want: true},
		{name: "true", fields: fields{needSpecialCharactersCount: 4, specialCharacters: specials}, args: args{pass: "@a!s*f%efd"}, want: true},
		{name: "true", fields: fields{needSpecialCharactersCount: 1, specialCharacters: specials}, args: args{pass: "@a!s*f%efd"}, want: true},
		{name: "false", fields: fields{needSpecialCharactersCount: 1, specialCharacters: specials}, args: args{pass: "asfefd"}, want: false},
		{name: "false", fields: fields{needSpecialCharactersCount: 2, specialCharacters: specials}, args: args{pass: "a#sfefd"}, want: false},
		{name: "no need", fields: fields{needSpecialCharactersCount: 0, specialCharacters: specials}, args: args{pass: "asfefd"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Password{
				specialCharacters:          tt.fields.specialCharacters,
				minChar:                    tt.fields.minChar,
				maxChar:                    tt.fields.maxChar,
				needNumberCount:            tt.fields.needNumberCount,
				needUpperCharactersCount:   tt.fields.needUpperCharactersCount,
				needSpecialCharactersCount: tt.fields.needSpecialCharactersCount,
			}
			if got := p.haveSpecialCharacters(tt.args.pass); got != tt.want {
				t.Errorf("Password.haveSpecialCharacters() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_countUpperCharactersOfString(t *testing.T) {
	type args struct {
		pass string
	}
	tests := []struct {
		name      string
		args      args
		wantTotal int
	}{
		{name: "want five", args: args{pass: "Aa3Sd5Rf6FgH7h8"}, wantTotal: 5},
		{name: "want zero", args: args{pass: "adf!^ fd gh"}, wantTotal: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotTotal := countUpperCharactersOfString(tt.args.pass); gotTotal != tt.wantTotal {
				t.Errorf("countUpperCharactersOfString() = %v, want %v", gotTotal, tt.wantTotal)
			}
		})
	}
}

func TestPassword_haveUpperCharacters(t *testing.T) {
	type fields struct {
		specialCharacters          []string
		minChar                    uint8
		maxChar                    uint
		needNumberCount            uint8
		needUpperCharactersCount   uint8
		needSpecialCharactersCount uint8
	}
	type args struct {
		pass string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{name: "true", fields: fields{needUpperCharactersCount: 1}, args: args{pass: "aAsf%efd"}, want: true},
		{name: "true", fields: fields{needUpperCharactersCount: 4}, args: args{pass: "@ASDFa!s*f%efd"}, want: true},
		{name: "true", fields: fields{needUpperCharactersCount: 1}, args: args{pass: "@aE!s*f%efd"}, want: true},
		{name: "false", fields: fields{needUpperCharactersCount: 1}, args: args{pass: "asfefd"}, want: false},
		{name: "false", fields: fields{needUpperCharactersCount: 2}, args: args{pass: "a#Bsfefd"}, want: false},
		{name: "no need", fields: fields{needUpperCharactersCount: 0}, args: args{pass: "asfefd"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Password{
				specialCharacters:          tt.fields.specialCharacters,
				minChar:                    tt.fields.minChar,
				maxChar:                    tt.fields.maxChar,
				needNumberCount:            tt.fields.needNumberCount,
				needUpperCharactersCount:   tt.fields.needUpperCharactersCount,
				needSpecialCharactersCount: tt.fields.needSpecialCharactersCount,
			}
			if got := p.haveUpperCharacters(tt.args.pass); got != tt.want {
				t.Errorf("Password.haveUpperCharacters() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPassword_haveNumberChar(t *testing.T) {
	type fields struct {
		specialCharacters          []string
		minChar                    uint8
		maxChar                    uint
		needNumberCount            uint8
		needUpperCharactersCount   uint8
		needSpecialCharactersCount uint8
	}
	type args struct {
		pass string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{name: "true", fields: fields{needNumberCount: 1}, args: args{pass: "aA1sf%efd"}, want: true},
		{name: "true", fields: fields{needNumberCount: 4}, args: args{pass: "@AS1DF4a3!s79*f%efd"}, want: true},
		{name: "true", fields: fields{needNumberCount: 1}, args: args{pass: "@a1E!s*f%efd"}, want: true},
		{name: "false", fields: fields{needNumberCount: 1}, args: args{pass: "asfefd"}, want: false},
		{name: "false", fields: fields{needNumberCount: 2}, args: args{pass: "a#Bs2fefd"}, want: false},
		{name: "no need", fields: fields{needNumberCount: 0}, args: args{pass: "asfefd"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Password{
				specialCharacters:          tt.fields.specialCharacters,
				minChar:                    tt.fields.minChar,
				maxChar:                    tt.fields.maxChar,
				needNumberCount:            tt.fields.needNumberCount,
				needUpperCharactersCount:   tt.fields.needUpperCharactersCount,
				needSpecialCharactersCount: tt.fields.needSpecialCharactersCount,
			}
			if got := p.haveNumberChar(tt.args.pass); got != tt.want {
				t.Errorf("Password.haveNumberChar() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPassword_MinChar(t *testing.T) {
	type fields struct {
		specialCharacters          []string
		minChar                    uint8
		maxChar                    uint
		needNumberCount            uint8
		needUpperCharactersCount   uint8
		needSpecialCharactersCount uint8
	}
	type args struct {
		pass string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{name: "true", fields: fields{minChar: 1}, args: args{pass: "aA1sf%efd"}, want: true},
		{name: "true", fields: fields{minChar: 14}, args: args{pass: "@AS1DF4a3!s79*f%efd"}, want: true},
		{name: "true", fields: fields{minChar: 1}, args: args{pass: "@a1E!s*f%efd"}, want: true},
		{name: "false", fields: fields{minChar: 1}, args: args{pass: ""}, want: false},
		{name: "false", fields: fields{minChar: 2}, args: args{pass: "a"}, want: false},
		{name: "no need", fields: fields{minChar: 0}, args: args{pass: "asfefd"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Password{
				specialCharacters:          tt.fields.specialCharacters,
				minChar:                    tt.fields.minChar,
				maxChar:                    tt.fields.maxChar,
				needNumberCount:            tt.fields.needNumberCount,
				needUpperCharactersCount:   tt.fields.needUpperCharactersCount,
				needSpecialCharactersCount: tt.fields.needSpecialCharactersCount,
			}
			if got := p.MinChar(tt.args.pass); got != tt.want {
				t.Errorf("Password.MinChar() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPassword_MaxChar(t *testing.T) {
	type fields struct {
		specialCharacters          []string
		minChar                    uint8
		maxChar                    uint
		needNumberCount            uint8
		needUpperCharactersCount   uint8
		needSpecialCharactersCount uint8
	}
	type args struct {
		pass string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{name: "true", fields: fields{maxChar: 1}, args: args{pass: "a"}, want: true},
		{name: "true", fields: fields{maxChar: 4}, args: args{pass: "@S1D"}, want: true},
		{name: "true", fields: fields{maxChar: 10}, args: args{pass: "@a1E!s*f%e"}, want: true},
		{name: "false", fields: fields{maxChar: 1}, args: args{pass: "asfefd"}, want: false},
		{name: "false", fields: fields{maxChar: 2}, args: args{pass: "a#B"}, want: false},
		{name: "no need", fields: fields{maxChar: 0}, args: args{pass: "asfefdsad"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Password{
				specialCharacters:          tt.fields.specialCharacters,
				minChar:                    tt.fields.minChar,
				maxChar:                    tt.fields.maxChar,
				needNumberCount:            tt.fields.needNumberCount,
				needUpperCharactersCount:   tt.fields.needUpperCharactersCount,
				needSpecialCharactersCount: tt.fields.needSpecialCharactersCount,
			}
			if got := p.MaxChar(tt.args.pass); got != tt.want {
				t.Errorf("Password.MaxChar() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPassword_Check(t *testing.T) {
	type args struct {
		pass string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "err-number", args: args{pass: "1a2s3dc5v"}, wantErr: true},
		{name: "err-upperCase", args: args{pass: "12ASF12s3d"}, wantErr: true},
		{name: "err-special-char", args: args{pass: "12AS!@#$AF123D"}, wantErr: true},
		{name: "err-max-char", args: args{pass: "12AS!@#$AF123D12AS!@#$AF123D"}, wantErr: true},
		{name: "pass", args: args{pass: "12A*S!@#$AF123D"}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(4, 10, 5, 5, 5)
			if err := p.Check(tt.args.pass); (err != nil) != tt.wantErr {
				t.Errorf("Password.Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	tests = []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "err-number", args: args{pass: "asdcv"}, wantErr: true},
		{name: "err-upperCase", args: args{pass: "a1sdcv"}, wantErr: true},
		{name: "err-special-char", args: args{pass: "a1sAdcv"}, wantErr: true},
		{name: "err-max-char", args: args{pass: "a1sAd@cv"}, wantErr: true},
		{name: "pass", args: args{pass: "1sAd@cv"}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(4, 7, 1, 1, 1)
			if err := p.Check(tt.args.pass); (err != nil) != tt.wantErr {
				t.Errorf("Password.Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
