package com.Devansh.Authentication_System.io;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@Builder
@NoArgsConstructor
public class ProfileRequest {
    @NotBlank(message = "Name is required ")
    private String name;


    @NotNull(message = "Please enter a valid email address.")
//    @Email(message = "Email is required") this annotation does not
    @Pattern(
            regexp = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
            message = "Please enter a valid email address."
    )
    private String email;

    @NotBlank(message = "Password is required.")
    @Size(min = 8, max = 72,
            message = "Password must be between 8 and 72 characters long")
    private String password;

}
