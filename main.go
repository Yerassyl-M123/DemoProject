package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"test/cmd"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type item struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Price int    `json:"price"`
}

type users struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

var db *sql.DB

func main() {
	var err error
	err = godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbSSLMode := os.Getenv("DB_SSLMODE")

	dbConnStr := "user=" + dbUser + " password=" + dbPassword + " dbname=" + dbName + " sslmode=" + dbSSLMode

	db, err = sql.Open("postgres", dbConnStr)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	defer db.Close()

	server := gin.Default()

	store := cookie.NewStore([]byte("secret"))
	store.Options(sessions.Options{
		MaxAge: 1 * 60,
	})
	server.Use(sessions.Sessions("mysession", store))

	server.Use(sessionTimeout())

	server.LoadHTMLGlob("templates/*")
	server.GET("/home", authRequired(homePage))
	server.POST("/add", authRequired(addItem))
	server.POST("/delete", authRequired(deleteItemByID))
	server.POST("/basket", authRequired(addToBasket))
	server.POST("/confirm", confirmBasket)

	server.GET("/signUpPage", signUpPage)
	server.POST("/signup", signUp)
	server.GET("/signInPage", signInPage)
	server.POST("/signin", signIn)
	server.GET("/logout", logout)

	server.Run(":8080")
}

func homePage(c *gin.Context) {
	rows, err := db.Query("SELECT id, name, price FROM items")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var items []item
	for rows.Next() {
		var i item
		if err := rows.Scan(&i.ID, &i.Name, &i.Price); err != nil {
			log.Fatal(err)
		}
		items = append(items, i)
	}

	session := sessions.Default(c)
	userID := session.Get("user_id")

	var user users
	db.QueryRow("SELECT id, username, email FROM users WHERE id = $1", userID).Scan(&user.ID, &user.Username, &user.Email)

	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	basket := session.Get("basket")
	var totalPrice int
	if basket == nil {
		basket = []item{}
	} else {
		var basketItems []item
		for _, itemID := range basket.([]string) {
			var i item
			err := db.QueryRow("SELECT id, name, price FROM items WHERE id = $1", itemID).Scan(&i.ID, &i.Name, &i.Price)
			if err != nil {
				log.Fatal(err)
			}
			basketItems = append(basketItems, i)
			totalPrice = totalPrice + i.Price
		}
		basket = basketItems
	}

	c.HTML(http.StatusOK, "home.html", gin.H{
		"items":      items,
		"user":       user,
		"basket":     basket,
		"totalPrice": totalPrice,
	})
}

func addItem(c *gin.Context) {
	name := c.PostForm("item-name")
	priceStr := c.PostForm("item-price")

	price, err := strconv.Atoi(priceStr)
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid price")
		return
	}

	var newItem item
	err = db.QueryRow("INSERT INTO items (name, price) VALUES ($1, $2) RETURNING id", name, price).Scan(&newItem.ID)
	if err != nil {
		log.Fatal(err)
	}

	c.Redirect(http.StatusFound, "/home")
}

func deleteItemByID(c *gin.Context) {
	idStr := c.PostForm("delete-id")

	id, err := strconv.Atoi(idStr)
	if err != nil {
		log.Fatal(err)
	}
	db.QueryRow("DELETE FROM items WHERE ID = $1", id)

	c.Redirect(http.StatusFound, "/home")
}

func signUpPage(c *gin.Context) {
	c.HTML(http.StatusOK, "signUp.html", nil)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func signUp(c *gin.Context) {
	userName := c.PostForm("user-name")
	userEmail := c.PostForm("user-email")
	userPass := c.PostForm("user-password")

	if userName == "" || len(userPass) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters long"})
		return
	}

	var existingUser users
	err := db.QueryRow("SELECT id FROM users WHERE email = $1", userEmail).Scan(&existingUser.ID)
	if err != sql.ErrNoRows {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already in use"})
		return
	}

	hashedPassword, err := hashPassword(userPass)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	var newUser users
	err = db.QueryRow("INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id", userName, userEmail, hashedPassword).Scan(&newUser.ID)
	if err != nil {
		log.Fatal(err)
	}

	c.Redirect(http.StatusFound, "/home")
}

func signInPage(c *gin.Context) {
	c.HTML(http.StatusOK, "signIn.html", nil)
}

func signIn(c *gin.Context) {
	email := c.PostForm("user-email")
	password := c.PostForm("user-password")

	var storedUser users
	err := db.QueryRow("SELECT id, username, email, password FROM users WHERE email = $1", email).Scan(&storedUser.ID, &storedUser.Username, &storedUser.Email, &storedUser.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	if !checkPasswordHash(password, storedUser.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	session := sessions.Default(c)
	session.Set("user_id", storedUser.ID)
	session.Set("user_email", storedUser.Email)
	session.Save()

	c.Redirect(http.StatusFound, "/home")
}
func logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()

	c.Redirect(http.StatusFound, "/signInPage")
}

func authRequired(handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil {
			c.Redirect(http.StatusFound, "/signInPage")
			return
		}
		handler(c)
	}
}

func sessionTimeout() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		lastActivity := session.Get("last_activity")

		if lastActivity != nil {
			lastActivityTime := lastActivity.(int64)
			if time.Now().Unix()-lastActivityTime > 1*60 {
				session.Clear()
				session.Save()
				c.Redirect(http.StatusFound, "/signInPage")
				c.Abort()
				return
			}
		}

		session.Set("last_activity", time.Now().Unix())
		session.Save()
		c.Next()
	}
}

func addToBasket(c *gin.Context) {
	itemID := c.PostForm("item-id")
	session := sessions.Default(c)
	basket := session.Get("basket")
	if basket == nil {
		basket = []string{}
	}

	basket = append(basket.([]string), itemID)
	session.Set("basket", basket)
	session.Save()

	c.Redirect(http.StatusFound, "/home")
}

func confirmBasket(c *gin.Context) {
	session := sessions.Default(c)
	userEmail := session.Get("user_email")
	basket := session.Get("basket")

	if userEmail == nil || basket == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No items in basket"})
		return
	}

	body := "Your order:\n\n"
	var totalPrice int
	for _, itemID := range basket.([]string) {
		var i item
		err := db.QueryRow("SELECT name, price FROM items WHERE id = $1", itemID).Scan(&i.Name, &i.Price)
		if err != nil {
			log.Fatal(err)
		}
		body += fmt.Sprintf("Name: %s, Price: %d\n", i.Name, i.Price)
		totalPrice += i.Price
	}
	body += fmt.Sprintf("\nTotal Price: %d", totalPrice)

	err := cmd.SendMessage([]string{userEmail.(string)}, "Your Order Confirmation", body)
	if err != nil {
		log.Fatalf("Error sending email: %v", err)
	}

	session.Delete("basket")
	session.Save()

	c.Redirect(http.StatusFound, "/home")
}
