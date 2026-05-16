import { CommonModule } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { RegisterRequest } from '../models/auth.models';
import { AuthService } from '../services/auth.service';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './register.component.html'
})
export class RegisterComponent {
  email = '';
  username = '';
  fullName = '';
  password = '';
  confirmPassword = '';
  errorMessage = '';
  loading = false;

  constructor(
    private readonly authService: AuthService,
    private readonly router: Router
  ) {}

  onRegister(): void {
    this.errorMessage = '';

    if (!this.email || !this.password) {
      this.errorMessage = 'Emailul și parola sunt obligatorii.';
      return;
    }

    if (this.password !== this.confirmPassword) {
      this.errorMessage = 'Parolele nu se potrivesc.';
      return;
    }

    const data: RegisterRequest = {
      email: this.email,
      password: this.password
    };

    if (this.username.trim()) {
      data.username = this.username.trim();
    }

    if (this.fullName.trim()) {
      data.full_name = this.fullName.trim();
    }

    this.loading = true;

    this.authService.register(data).subscribe({
      next: () => {
        this.loading = false;
        this.router.navigate(['/login']);
      },
      error: (error: HttpErrorResponse) => {
        this.loading = false;
        this.errorMessage = this.getRegisterErrorMessage(error);
      }
    });
  }

  private getRegisterErrorMessage(error: HttpErrorResponse): string {
    if (error.status === 400 || error.status === 409) {
      return 'Există deja un cont cu acest email.';
    }

    return 'A apărut o eroare la înregistrare.';
  }
}
