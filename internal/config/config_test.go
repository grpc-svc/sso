package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMustLoadByPath_Success(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test_config.yaml")

	configContent := `
env: "test"
storage_path: "/tmp/test.db"
token_ttl: 2h
grpc:
  port: 50051
  timeout: 10s
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err, "не удалось создать тестовый конфиг файл")

	cfg := MustLoadByPath(configPath)

	assert.NotNil(t, cfg, "конфигурация не должна быть nil")
	assert.Equal(t, "test", cfg.Env, "env должен быть 'test'")
	assert.Equal(t, "/tmp/test.db", cfg.StoragePath, "storage_path должен совпадать")
	assert.Equal(t, 2*time.Hour, cfg.TokenTTL, "token_ttl должен быть 2 часа")
	assert.Equal(t, 50051, cfg.GRPC.Port, "GRPC порт должен быть 50051")
	assert.Equal(t, 10*time.Second, cfg.GRPC.Timeout, "GRPC timeout должен быть 10 секунд")
}

func TestMustLoadByPath_FileNotFound(t *testing.T) {
	nonExistentPath := "/path/that/does/not/exist/config.yaml"

	assert.Panics(t, func() {
		MustLoadByPath(nonExistentPath)
	}, "должна быть паника при отсутствии конфиг файла")
}

func TestMustLoadByPath_InvalidYAML(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "invalid_config.yaml")

	invalidContent := `
env: "test"
storage_path: /tmp/test.db
token_ttl: invalid_duration_format
`
	err := os.WriteFile(configPath, []byte(invalidContent), 0644)
	require.NoError(t, err)

	assert.Panics(t, func() {
		MustLoadByPath(configPath)
	}, "должна быть паника при невалидном YAML")
}

func TestMustLoadByPath_MissingRequiredField(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "incomplete_config.yaml")

	incompleteContent := `
env: "test"
token_ttl: 1h
grpc:
  port: 50051
  timeout: 10s
`
	err := os.WriteFile(configPath, []byte(incompleteContent), 0644)
	require.NoError(t, err)

	assert.Panics(t, func() {
		MustLoadByPath(configPath)
	}, "должна быть паника при отсутствии обязательного поля")
}

func TestMustLoadByPath_DefaultValues(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "minimal_config.yaml")

	minimalContent := `
storage_path: "/tmp/test.db"
token_ttl: 1h
grpc:
  port: 44044
  timeout: 5h
`
	err := os.WriteFile(configPath, []byte(minimalContent), 0644)
	require.NoError(t, err)

	cfg := MustLoadByPath(configPath)

	assert.Equal(t, "local", cfg.Env, "env должен иметь дефолтное значение 'local'")
	assert.Equal(t, "/tmp/test.db", cfg.StoragePath)
	assert.Equal(t, time.Hour, cfg.TokenTTL)
}

func TestMustLoadByPath_RealConfigFile(t *testing.T) {
	realConfigPath := "../../config/local.yaml"

	if _, err := os.Stat(realConfigPath); os.IsNotExist(err) {
		t.Skip("пропускаем тест: реальный конфиг файл не найден")
	}

	cfg := MustLoadByPath(realConfigPath)

	assert.NotNil(t, cfg)
	assert.Equal(t, "local", cfg.Env)
	assert.Equal(t, "./storage/sso.db", cfg.StoragePath)
	assert.Equal(t, time.Hour, cfg.TokenTTL)
	assert.Equal(t, 44044, cfg.GRPC.Port)
	assert.Equal(t, 10*time.Second, cfg.GRPC.Timeout)
}

func TestConfig_StructTags(t *testing.T) {

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "tags_test.yaml")

	content := `
env: "production"
storage_path: "/var/lib/sso.db"
token_ttl: 24h
grpc:
  port: 9090
  timeout: 30s
`
	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg := MustLoadByPath(configPath)

	assert.IsType(t, "", cfg.Env, "Env должен быть string")
	assert.IsType(t, "", cfg.StoragePath, "StoragePath должен быть string")
	assert.IsType(t, time.Duration(0), cfg.TokenTTL, "TokenTTL должен быть time.Duration")
	assert.IsType(t, GRPCConfig{}, cfg.GRPC, "GRPC должен быть GRPCConfig")

	assert.IsType(t, 0, cfg.GRPC.Port, "Port должен быть int")
	assert.IsType(t, time.Duration(0), cfg.GRPC.Timeout, "Timeout должен быть time.Duration")
}

func BenchmarkMustLoadByPath(b *testing.B) {
	tempDir := b.TempDir()
	configPath := filepath.Join(tempDir, "bench_config.yaml")

	content := `
env: "test"
storage_path: "/tmp/test.db"
token_ttl: 1h
grpc:
  port: 50051
  timeout: 10s
`
	err := os.WriteFile(configPath, []byte(content), 0644)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = MustLoadByPath(configPath)
	}
}
