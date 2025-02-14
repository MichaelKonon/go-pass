package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/boltdb/bolt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

const dbFile = "passwords.db"
const bucketName = "Passwords"
var encryptionKey = []byte("examplekey123456") // Должен быть 16, 24 или 32 байта

func encrypt(data string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	encrypter := cipher.NewCFBEncrypter(block, iv)
	encrypter.XORKeyStream(ciphertext[aes.BlockSize:], []byte(data))
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(data string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	decrypter := cipher.NewCFBDecrypter(block, iv)
	decrypter.XORKeyStream(ciphertext, ciphertext)
	return string(ciphertext), nil
}

func savePassword(db *bolt.DB, service, password string) error {
	encryptedPass, err := encrypt(password)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		return b.Put([]byte(service), []byte(encryptedPass))
	})
}

func getPassword(db *bolt.DB, service string) (string, error) {
	var encryptedPass []byte
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		encryptedPass = b.Get([]byte(service))
		return nil
	})
	if err != nil {
		return "", err
	}
	if encryptedPass == nil {
		return "", fmt.Errorf("password not found")
	}
	return decrypt(string(encryptedPass))
}

func deletePassword(db *bolt.DB, service string) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		return b.Delete([]byte(service))
	})
}

func main() {
	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	})

	application := app.New()
	window := application.NewWindow("Password Manager")

	serviceEntry := widget.NewEntry()
	serviceEntry.SetPlaceHolder("Введите сервис")
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Введите пароль")
	resultLabel := widget.NewLabel("")

	saveButton := widget.NewButton("Сохранить", func() {
		service := serviceEntry.Text
		password := passwordEntry.Text
		if service == "" || password == "" {
			resultLabel.SetText("Введите сервис и пароль")
			return
		}
		if err := savePassword(db, service, password); err != nil {
			resultLabel.SetText("Ошибка: " + err.Error())
		} else {
			resultLabel.SetText("Пароль сохранен!")
		}
	})

	getButton := widget.NewButton("Получить", func() {
		service := serviceEntry.Text
		if service == "" {
			resultLabel.SetText("Введите сервис")
			return
		}
		password, err := getPassword(db, service)
		if err != nil {
			resultLabel.SetText("Ошибка: " + err.Error())
		} else {
			resultLabel.SetText("Пароль: " + password)
		}
	})

	deleteButton := widget.NewButton("Удалить", func() {
		service := serviceEntry.Text
		if service == "" {
			resultLabel.SetText("Введите сервис")
			return
		}
		if err := deletePassword(db, service); err != nil {
			resultLabel.SetText("Ошибка удаления: " + err.Error())
		} else {
			resultLabel.SetText("Пароль удален!")
		}
	})

	exitButton := widget.NewButton("Выход", func() {
		application.Quit()
	})

	content := container.NewVBox(
		widget.NewLabel("Менеджер паролей"),
		serviceEntry,
		passwordEntry,
		saveButton,
		getButton,
		deleteButton,
		exitButton,
		resultLabel,
	)

	window.SetContent(content)
	window.ShowAndRun()
}
