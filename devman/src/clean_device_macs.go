package main
import (
	"fmt"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)
func main() {
	db, err := gorm.Open(sqlite.Open("/etc/devman/devman.db"), &gorm.Config{})
	if err != nil { fmt.Println("err:", err); return }
	r := db.Exec("DELETE FROM device_macs")
	fmt.Printf("cleaned device_macs: %d rows\n", r.RowsAffected)
}
