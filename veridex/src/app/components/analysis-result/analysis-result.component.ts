import { NgClass } from '@angular/common';
import { Component, Input } from '@angular/core';
import { AnalysisResponse, AnalysisRisk } from '../../analysis.service';

@Component({
  selector: 'app-analysis-result',
  standalone: true,
  imports: [NgClass],
  templateUrl: './analysis-result.component.html'
})
export class AnalysisResultComponent {
  @Input({ required: true }) result!: AnalysisResponse;

  riskLabel(risk: AnalysisRisk): string {
    return {
      safe: 'SIGUR',
      suspicious: 'SUSPICIOS',
      dangerous: 'PERICULOS'
    }[risk];
  }

  riskClass(risk: AnalysisRisk): string {
    return {
      safe: 'safe',
      suspicious: 'amber',
      dangerous: 'danger'
    }[risk];
  }

  scoreColorClass(risk: AnalysisRisk): string {
    return {
      safe: 'green',
      suspicious: 'amber',
      dangerous: 'red'
    }[risk];
  }

  scoreStroke(risk: AnalysisRisk): string {
    return {
      safe: '#1D9E75',
      suspicious: '#EF9F27',
      dangerous: '#E24B4A'
    }[risk];
  }

  scoreOffset(score: number): number {
    const circumference = 175.9;
    const normalizedScore = Math.max(0, Math.min(100, score));
    return circumference - (normalizedScore / 100) * circumference;
  }
}
