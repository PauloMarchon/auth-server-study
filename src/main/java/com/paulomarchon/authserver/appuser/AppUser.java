package com.paulomarchon.authserver.appuser;

import com.paulomarchon.authserver.appuser.role.Role;
import jakarta.persistence.*;
import lombok.Builder;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Set;
import java.util.UUID;

@Entity
@Builder
@Table(name = "appuser",
    uniqueConstraints = {
        @UniqueConstraint(columnNames = "email"),
        @UniqueConstraint(columnNames = "username")
    })
@EntityListeners(AuditingEntityListener.class)
public class AppUser implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    private String email;
    private String password;
    private String username;
    private String avatarImageUrl;
    private String bannerImageUrl;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "modified_at", nullable = false)
    private LocalDateTime updatedAt;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "appuser_roles",
        joinColumns = @JoinColumn(name = "appuser_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> authorities;

    @Builder.Default
    private boolean isEnabled = false;
    @Builder.Default
    private boolean isPremiumAccount = false;
    @Builder.Default
    private boolean isAccountNonExpired = true;
    @Builder.Default
    private boolean isAccountNonLocked = true;
    @Builder.Default
    private boolean isCredentialsNonExpired = true;

    public AppUser() {

    }

    public AppUser(String email, String password, String username, Set<Role> authorities) {
        this.email = email;
        this.password = password;
        this.username = username;
        this.authorities = authorities;
    }

    public AppUser(UUID id, String email, String password, String username, String avatarImageUrl, String bannerImageUrl, LocalDateTime createdAt, LocalDateTime updatedAt, Set<Role> authorities, boolean isEnabled, boolean isPremiumAccount, boolean isAccountNonExpired, boolean isAccountNonLocked, boolean isCredentialsNonExpired) {
        this.id = id;
        this.email = email;
        this.password = password;
        this.username = username;
        this.avatarImageUrl = avatarImageUrl;
        this.bannerImageUrl = bannerImageUrl;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.authorities = authorities;
        this.isEnabled = isEnabled;
        this.isPremiumAccount = isPremiumAccount;
        this.isAccountNonExpired = isAccountNonExpired;
        this.isAccountNonLocked = isAccountNonLocked;
        this.isCredentialsNonExpired = isCredentialsNonExpired;
    }

    public UUID getId() {return id;}

    public String getEmail() {return email;}

    public void setEmail(String email) {
        this.email = email;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getAvatarImageUrl() {
        return avatarImageUrl;
    }

    public void setAvatarImageUrl(String avatarImageUrl) {
        this.avatarImageUrl = avatarImageUrl;
    }

    public String getBannerImageUrl() {
        return bannerImageUrl;
    }

    public void setBannerImageUrl(String bannerImageUrl) {
        this.bannerImageUrl = bannerImageUrl;
    }

    public void setAuthorities(Set<Role> authorities) {
        this.authorities = authorities;
    }

    public LocalDateTime getCreatedAt() {return createdAt;}

    public LocalDateTime getUpdatedAt() {return updatedAt;}

    public boolean isPremiumAccount() {
        return isPremiumAccount;
    }

    public void setPremiumAccount(boolean freeAccount) {
        isPremiumAccount = freeAccount;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return isAccountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return isAccountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return isCredentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return isEnabled;
    }

    public void setEnabled(boolean enabled) {
        isEnabled = enabled;
    }

    public void setAccountNonExpired(boolean accountNonExpired) {
        isAccountNonExpired = accountNonExpired;
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        isAccountNonLocked = accountNonLocked;
    }

    public void setCredentialsNonExpired(boolean credentialsNonExpired) {isCredentialsNonExpired = credentialsNonExpired;}
}
