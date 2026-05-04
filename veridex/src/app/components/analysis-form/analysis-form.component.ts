import { Component, EventEmitter, Input, Output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AnalysisResponse, AnalysisService, ScanType } from '../../analysis.service';
import { AnalysisResultComponent } from '../analysis-result/analysis-result.component';

type AnalyzeMode = ScanType;

@Component({
  selector: 'app-analysis-form',
  standalone: true,
  imports: [FormsModule, AnalysisResultComponent],
  templateUrl: './analysis-form.component.html'
})
export class AnalysisFormComponent {
  @Output() analysisCompleted = new EventEmitter<void>();

  analyzeMode = signal<AnalyzeMode>('sms');
  analysisInput = signal('');
  showResult = signal(false);
  analysisResult = signal<AnalysisResponse | null>(null);
  analysisLoading = signal(false);
  analysisError = signal('');
  analysisValidation = signal('');

  readonly examples: Record<string, string> = {
    scam1: 'Stimate client BCR, contul dvs a fost suspendat temporar. Accesati urgent: http://bcr-secure-verify.net/confirm pentru reactivare.',
    scam2: 'Coletul dvs #RO48291 asteapta confirmare adresa. Taxa livrare: 1.5 RON. Platiti ACUM: http://fan-courier-ro.cc/pay',
    scam3: 'FELICITARI! Esti castigatorul a 50.000 RON la Loteria Nationala. Revendicati premiul in 24h: http://ln-premii.com/claim?id=8821'
  };

  readonly urlExamples: Record<string, string> = {
    bank: 'http://bcr-secure-verify.net/confirm',
    delivery: 'http://fan-courier-ro.cc/pay',
    prize: 'http://ln-premii.com/claim?id=8821'
  };

  constructor(private readonly analysisService: AnalysisService) {}

  setAnalyzeMode(mode: AnalyzeMode) {
    this.analyzeMode.set(mode);
    this.resetAnalysis();
    this.analysisInput.set('');
  }

  loadExample(key: string) {
    this.analysisInput.set(this.examples[key]);
    this.resetAnalysis();
  }

  loadUrlExample(key: string) {
    this.analysisInput.set(this.urlExamples[key]);
    this.resetAnalysis();
  }

  analyze() {
    const input = this.analysisInput().trim();
    const mode = this.analyzeMode();

    if (!input) {
      this.analysisValidation.set(mode === 'sms' ? 'Introdu un mesaj pentru analiza.' : 'Introdu un link pentru analiza.');
      this.showResult.set(false);
      this.analysisResult.set(null);
      this.analysisError.set('');
      return;
    }

    this.showResult.set(true);
    this.analysisLoading.set(true);
    this.analysisError.set('');
    this.analysisValidation.set('');
    this.analysisResult.set(null);

    const request = mode === 'sms'
      ? this.analysisService.analyzeSms(input)
      : this.analysisService.analyzeUrl(input);

    request.subscribe({
      next: (response) => {
        this.analysisResult.set(response);
        this.analysisLoading.set(false);
        this.analysisCompleted.emit();
      },
      error: () => {
        this.analysisError.set('Backend-ul nu poate fi accesat momentan. Verifica daca serverul ruleaza la http://127.0.0.1:8002.');
        this.analysisLoading.set(false);
      }
    });
  }

  private resetAnalysis() {
    this.showResult.set(false);
    this.analysisResult.set(null);
    this.analysisError.set('');
    this.analysisValidation.set('');
  }
}
