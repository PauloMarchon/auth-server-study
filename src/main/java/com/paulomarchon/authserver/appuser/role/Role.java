package com.paulomarchon.authserver.appuser.role;

import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;

@Entity
@Table(name = "roles")
public class Role implements GrantedAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Enumerated(EnumType.STRING)
    private RoleName authority;

    public Role() {
    }

    public Role(RoleName authority) {
        this.authority = authority;
    }

    public Integer getId() {
        return id;
    }

    @Override
    public String getAuthority() {
        return authority.name();
    }
}
