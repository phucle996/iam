package id

import (
	cryptorand "crypto/rand"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

var ErrInvalidULID = errors.New("invalid ulid")

type Generator struct {
	mu      sync.Mutex
	entropy io.Reader
}

func New(entropy io.Reader) *Generator {
	if entropy == nil {
		entropy = cryptorand.Reader
	}

	return &Generator{
		entropy: ulid.Monotonic(entropy, 0),
	}
}

func (g *Generator) Generate() (string, error) {
	return g.GenerateAt(time.Now().UTC())
}

func (g *Generator) MustGenerate() string {
	id, err := g.Generate()
	if err != nil {
		panic(err)
	}
	return id
}

func (g *Generator) GenerateAt(t time.Time) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	id, err := ulid.New(ulid.Timestamp(t.UTC()), g.entropy)
	if err != nil {
		return "", err
	}

	return id.String(), nil
}

func (g *Generator) Parse(value string) (ulid.ULID, error) {
	value = normalize(value)

	id, err := ulid.ParseStrict(value)
	if err != nil {
		return ulid.ULID{}, ErrInvalidULID
	}

	return id, nil
}

func (g *Generator) Validate(value string) error {
	_, err := g.Parse(value)
	return err
}

func (g *Generator) IsValid(value string) bool {
	return g.Validate(value) == nil
}

func (g *Generator) Time(value string) (time.Time, error) {
	id, err := g.Parse(value)
	if err != nil {
		return time.Time{}, err
	}

	return time.UnixMilli(int64(id.Time())).UTC(), nil
}

var defaultGenerator = New(nil)

func Generate() (string, error) {
	return defaultGenerator.Generate()
}

func MustGenerate() string {
	return defaultGenerator.MustGenerate()
}

func Parse(value string) (ulid.ULID, error) {
	return defaultGenerator.Parse(value)
}

func Validate(value string) error {
	return defaultGenerator.Validate(value)
}

func IsValid(value string) bool {
	return defaultGenerator.IsValid(value)
}

func Time(value string) (time.Time, error) {
	return defaultGenerator.Time(value)
}

func normalize(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}
