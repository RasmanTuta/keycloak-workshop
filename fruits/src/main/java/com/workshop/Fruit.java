package com.workshop;

import java.util.Objects;

public class Fruit {
    public String name;
    public String description;

    public Fruit() {
    }

    public Fruit(String name, String description) {
        this.name = name;
        this.description = description;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Fruit fruit = (Fruit) o;
        return Objects.equals(name, fruit.name) && Objects.equals(description, fruit.description);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, description);
    }
}
