package com.abohosale.security.SecurityGate.auth.common.login;

import lombok.Data;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class SignUpResult {
    @NonNull
    String message;
}
