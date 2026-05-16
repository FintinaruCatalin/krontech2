import { DecimalPipe, NgClass } from '@angular/common';
import { Component, OnInit, ViewChild } from '@angular/core';
import { AnalysisRisk, AnalysisService, ScanHistoryItem, StatsResponse } from '../../analysis.service';
import { AnalysisFormComponent } from '../../components/analysis-form/analysis-form.component';
import { HeroStatsComponent } from '../../components/hero-stats/hero-stats.component';
import { HistoryComponent } from '../../components/history/history.component';

@Component({
  selector: 'app-analysis-page',
  standalone: true,
  imports: [DecimalPipe, NgClass, HeroStatsComponent, AnalysisFormComponent, HistoryComponent],
  templateUrl: './analysis-page.component.html'
})
export class AnalysisPageComponent implements OnInit {
  @ViewChild(HistoryComponent) private historyComponent?: HistoryComponent;

  stats: StatsResponse = {
    total_analyses: 0,
    alerts_generated: 0,
    risk_rate: 0
  };
  currentHistory: ScanHistoryItem[] = [];

  constructor(private readonly analysisService: AnalysisService) {}

  ngOnInit(): void {
    this.loadStats();
  }

  handleAnalysisCompleted(): void {
    this.historyComponent?.refresh();
    this.loadStats();
  }

  handleHistoryLoaded(items: ScanHistoryItem[]): void {
    this.currentHistory = items;
  }

  loadStats(): void {
    this.analysisService.getStats().subscribe({
      next: (stats) => {
        this.stats = stats;
      },
      error: () => {
        this.stats = {
          total_analyses: 0,
          alerts_generated: 0,
          risk_rate: 0
        };
      }
    });
  }

  totalAnalyses(): number {
    return this.stats.total_analyses;
  }

  alertsCount(): number {
    return this.stats.alerts_generated;
  }

  riskRate(): number {
    return this.stats.risk_rate;
  }

  latestScanRisk(): string {
    const latestScan = this.currentHistory.reduce<ScanHistoryItem | undefined>((latest, item) => {
      if (!latest) {
        return item;
      }

      return new Date(item.created_at).getTime() > new Date(latest.created_at).getTime() ? item : latest;
    }, undefined);

    return latestScan ? this.riskLabel(latestScan.risk) : 'N/A';
  }

  smsScansCount(): number {
    return this.currentHistory.filter((item) => item.scan_type === 'sms').length;
  }

  urlScansCount(): number {
    return this.currentHistory.filter((item) => item.scan_type === 'url').length;
  }

  riskLabel(risk: string): string {
    return {
      safe: 'Safe',
      suspicious: 'Suspicious',
      dangerous: 'Dangerous'
    }[risk as AnalysisRisk] ?? risk;
  }

  riskClass(risk: string): string {
    return {
      safe: 'safe',
      suspicious: 'amber',
      dangerous: 'danger'
    }[risk as AnalysisRisk] ?? 'amber';
  }
}
