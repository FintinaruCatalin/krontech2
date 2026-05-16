import { NgClass } from '@angular/common';
import { Component, EventEmitter, OnInit, Output } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AnalysisRisk, AnalysisService, ScanHistoryItem, ScanType } from '../../analysis.service';

type HistoryFilter = ScanType | 'all';
type RiskFilter = AnalysisRisk | 'all';

@Component({
  selector: 'app-history',
  standalone: true,
  imports: [FormsModule, NgClass],
  templateUrl: './history.component.html'
})
export class HistoryComponent implements OnInit {
  @Output() historyLoaded = new EventEmitter<ScanHistoryItem[]>();

  selectedHistoryFilter: HistoryFilter = 'all';
  selectedRiskFilter: RiskFilter = 'all';
  historySearch = '';
  historyList: ScanHistoryItem[] = [];
  historyLoading = false;
  historyError = '';

  constructor(private readonly analysisService: AnalysisService) {}

  ngOnInit() {
    this.loadHistory();
  }

  setFilter(filter: HistoryFilter): void {
    this.selectedHistoryFilter = filter;
  }

  setRiskFilter(filter: RiskFilter): void {
    this.selectedRiskFilter = filter;
  }

  loadHistory(): void {
    this.historyLoading = true;
    this.historyError = '';

    this.analysisService.getHistory().subscribe({
      next: (items) => {
        this.historyList = items;
        this.historyLoading = false;
        this.historyLoaded.emit(items);
      },
      error: () => {
        this.historyList = [];
        this.historyError = 'Nu am putut incarca istoricul.';
        this.historyLoading = false;
        this.historyLoaded.emit([]);
      }
    });
  }

  refresh(): void {
    this.loadHistory();
  }

  visibleHistory(): ScanHistoryItem[] {
    const query = this.historySearch.trim().toLowerCase();

    return this.historyList.filter((item) => {
      const matchesType =
        this.selectedHistoryFilter === 'all' || item.scan_type === this.selectedHistoryFilter;
      const matchesRisk =
        this.selectedRiskFilter === 'all' || item.risk.toLowerCase() === this.selectedRiskFilter;
      const matchesSearch =
        query.length === 0 ||
        item.input_value.toLowerCase().includes(query) ||
        item.recommendation.toLowerCase().includes(query) ||
        item.risk.toLowerCase().includes(query) ||
        item.scan_type.toLowerCase().includes(query);

      return matchesType && matchesRisk && matchesSearch;
    });
  }

  inputPreview(value: string): string {
    return value.length > 110 ? `${value.slice(0, 110)}...` : value;
  }

  formatDateLocal(dateString: string): string {
    const normalizedDate = this.utcDateStringHasTimezone(dateString) ? dateString : `${dateString}Z`;
    const date = new Date(normalizedDate);

    if (Number.isNaN(date.getTime())) {
      return dateString;
    }

    return new Intl.DateTimeFormat('ro-RO', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    }).format(date);
  }

  getRiskClass(risk: string): string {
    const knownRisk = risk as AnalysisRisk;

    return {
      safe: 'safe',
      suspicious: 'amber',
      dangerous: 'danger'
    }[knownRisk] ?? 'amber';
  }

  riskLabel(risk: string): string {
    return {
      safe: 'Safe',
      suspicious: 'Suspicious',
      dangerous: 'Dangerous'
    }[risk as AnalysisRisk] ?? risk;
  }

  typeLabel(type: ScanType): string {
    return type.toUpperCase();
  }

  recommendationPreview(value: string): string {
    return value.length > 96 ? `${value.slice(0, 96)}...` : value;
  }

  private utcDateStringHasTimezone(dateString: string): boolean {
    return /(?:Z|[+-]\d{2}:?\d{2})$/i.test(dateString);
  }
}
