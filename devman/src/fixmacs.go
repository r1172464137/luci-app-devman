package main

import (
	"fmt"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type FixDevice struct {
	ID  int64  `gorm:"primaryKey"`
	MAC string `gorm:"column:mac"`
}

func (FixDevice) TableName() string { return "devices" }

type FixDeviceMAC struct {
	DeviceID int64  `gorm:"uniqueIndex:idx_dev_mac"`
	MAC      string `gorm:"uniqueIndex:idx_dev_mac"`
}

func (FixDeviceMAC) TableName() string { return "device_macs" }

func fixDeviceMACs() {
	db, err := gorm.Open(sqlite.Open("/etc/devman/devman.db"), &gorm.Config{})
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	var devs []FixDevice
	db.Where("mac != ''").Find(&devs)
	count := 0
	for _, d := range devs {
		result := db.Where(FixDeviceMAC{DeviceID: d.ID, MAC: d.MAC}).FirstOrCreate(&FixDeviceMAC{DeviceID: d.ID, MAC: d.MAC})
		if result.RowsAffected > 0 {
			count++
		}
	}
	fmt.Printf("Fixed %d device_macs entries\n", count)
}
