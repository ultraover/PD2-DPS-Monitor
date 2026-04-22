# PD2 DPS Overlay

A lightweight DPS (damage per second) overlay for Project Diablo 2.

This tool tracks your damage output in real time and displays useful combat metrics directly on screen.

---

## Features

* Real-time DPS tracking
* Multiple time windows (1s / 3s / 5s)
* Smoothed DPS (EMA)
* Hit counter
* Hits per second
* Last hit damage
* Total accumulated damage
* Movable overlay (position is saved automatically)
* Reset button to clear all stats

---

## Overlay Information

### **1s / 3s / 5s**

Damage per second calculated over the last:

* 1 second (instant)
* 3 seconds (short average)
* 5 seconds (stable average)

---

### **EMA**

Exponential Moving Average of DPS.

Provides a smoother and more stable value compared to raw DPS.

---

### **Hits**

Total number of successful hits detected.

---

### **Hits/s**

Number of hits per second.

---

### **Last**

Damage dealt by the most recent hit.

---

### **Total**

Total accumulated damage since last reset.

---

### **RESET**

Clears all tracked values:

* DPS
* Hits
* Total damage
* Internal averages

---

## Usage

* Drag the overlay using the icon on the left
* Click **RESET** to clear all values
* Position is saved automatically

---

## Limitations

* This tool **does not distinguish the source of damage**.
* It does not differentiate between:

  * Player damage
  * Minion damage
  * Damage from other entities (e.g. monsters fighting each other)
* It simply measures **global HP reduction events** detected in memory.

As a result, the displayed values represent:

> Total effective damage applied to entities, regardless of who caused it.

This means DPS values may be inflated or mixed depending on the situation (e.g. summons, party play, or environmental damage).

---

## Notes

* This overlay uses a lightweight GDI-based rendering system
* No external dependencies required
* Designed for minimal performance impact

---

## Disclaimer

This tool is intended for personal use and gameplay analysis.

Use at your own risk.

## Social Media

Find us @ https://discord.gg/zTwRPYhc
