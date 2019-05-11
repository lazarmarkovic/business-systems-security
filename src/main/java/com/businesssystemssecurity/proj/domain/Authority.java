package com.businesssystemssecurity.proj.domain;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Entity
@Table(name="authority")
public class Authority {
    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(name = "name", nullable = false, length = 50)
    private String name;

    @OneToMany(mappedBy = "authority", fetch = FetchType.LAZY, cascade = CascadeType.REFRESH)
    private Set<UserAuthority> userAuthorities = new HashSet<>();

    public long getId() {
        return id;
    }
    public void setId(long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }

    public Set<UserAuthority> getUserAuthorities() {
        return userAuthorities;
    }
    public void setUserAuthorities(Set<UserAuthority> userAuthorities) {
        this.userAuthorities = userAuthorities;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Authority authority = (Authority) o;
        return id == authority.id && Objects.equals(name, authority.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name);
    }

    @Override
    public String toString() {
        return "Authority{" +
                "id=" + id +
                ", name='" + name + '\'' +
                '}';
    }
}
