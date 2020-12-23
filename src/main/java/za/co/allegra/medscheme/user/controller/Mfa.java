package za.co.allegra.medscheme.user.controller;

import lombok.Data;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Data
public class Mfa {
    @NotNull
    @NotBlank
    private String mfaCode;
}
