package com.businesssystemssecurity.proj.domain;

import org.hibernate.validator.constraints.Length;

import javax.persistence.*;
import javax.validation.constraints.NotEmpty;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;


@Entity
@Table(name = "user")
public class User {

    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(name = "email", nullable = false, length = 100, unique = true)
    @NotEmpty(message = "*Email field cannot be empty.")
    private String email;

    @Column(name = "password", nullable = false, length = 200)
    @Length(min = 5, message = "*Your password must have at least 5 characters")
    @NotEmpty(message = "*Password field cannot be empty.")
    private String password;

    @Column(name = "first_name", nullable = false, length = 50)
    @NotEmpty(message = "*First name field cannot be empty.")
    private String firstName;

    @Column(name = "last_name", nullable = false, length = 100)
    @NotEmpty(message = "*Last name field cannot be empty.")
    private String lastName;

    @OneToMany(mappedBy = "user", fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    private Set<UserAuthority> userAuthorities = new HashSet<>();


    public User() {}

    public User(@NotEmpty(message = "*Email field cannot be empty.") String email, @Length(min = 5, message = "*Your password must have at least 5 characters") @NotEmpty(message = "*Password field cannot be empty.") String password, @NotEmpty(message = "*First name field cannot be empty.") String firstName, @NotEmpty(message = "*Last name field cannot be empty.") String lastName) {
        this();
        this.email = email;
        this.password = password;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    public long getId() {
        return id;
    }
    public void setId(long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }


    public String getFirstName() {
        return firstName;
    }
    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }
    public void setLastName(String lastName) {
        this.lastName = lastName;
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
        User user = (User) o;
        return id == user.id &&
                Objects.equals(email, user.email) &&
                Objects.equals(password, user.password) &&
                Objects.equals(firstName, user.firstName) &&
                Objects.equals(lastName, user.lastName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, email, password, firstName, lastName);
    }

    @Override
    public String toString() {
        return "User [id=" + id + ", email=" + email + ", password=" + password + ", firstName="
                + firstName + ", lastName=" + lastName + "]";
    }
}