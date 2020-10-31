package wcrypto

import (
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"go.uber.org/zap"
)

const TokenBitsLength = 6 /* bits / Base64 chr */ * 4 /* base64 block size */ * 3

func GenBase64Token(randr io.Reader, logger *zap.Logger) (string, error) {
	slog := logger.Sugar()

	start := time.Now()
	slog.Infow("Generating token...")
	defer slog.Infow("Generating token... Done.", "took", time.Since(start))

	buf := make([]byte, TokenBitsLength/8)
	if _, err := io.ReadFull(randr, buf); err != nil {
		return "", fmt.Errorf("Failed to generate token bits: %w", err)
	}

	token := base64.StdEncoding.EncodeToString(buf)
	return token, nil
}
