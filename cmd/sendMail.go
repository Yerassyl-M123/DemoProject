package cmd

import (
	"crypto/tls"
	"net/smtp"
)

func SendMessage(to []string, subject, body string) error {
	from := "boss.meyrkhanov@mail.ru"
	password := "2XyyanW2pipxtyY43GZa"

	// Установите настройки SMTP-сервера
	smtpHost := "smtp.mail.ru"
	smtpPort := "587"

	// Создайте SMTP клиент
	c, err := smtp.Dial(smtpHost + ":" + smtpPort)
	if err != nil {
		return err
	}
	defer c.Quit()

	// Установите STARTTLS
	if err = c.StartTLS(&tls.Config{
		ServerName: smtpHost,
	}); err != nil {
		return err
	}

	// Аутентификация
	auth := smtp.PlainAuth("", from, password, smtpHost)
	if err = c.Auth(auth); err != nil {
		return err
	}

	// Отправка письма
	if err = c.Mail(from); err != nil {
		return err
	}
	for _, addr := range to {
		if err = c.Rcpt(addr); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("From: " + from + "\r\n" +
		"To: " + to[0] + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body + "\r\n"))
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}

	return nil
}
