import { NgClass } from '@angular/common';
import { Component, EventEmitter, OnInit, Output } from '@angular/core';
import { AnalysisRisk, AnalysisService, ScanHistoryItem, ScanType } from '../../analysis.service';

type HistoryFilter = ScanType | 'all';

@Component({
  selector: 'app-history',
  standalone: true,
  imports: [NgClass],
  templateUrl: './history.component.html'
})
export class HistoryComponent implements OnInit {
  @Output() historyLoaded = new EventEmitter<ScanHistoryItem[]>();

  selectedHistoryFilter: HistoryFilter = 'all';
  historyList: ScanHistoryItem[] = [];
  historyLoading = false;
  historyError = '';

  constructor(private readonly analysisService: AnalysisService) {}

  ngOnInit() {
    this.loadHistory();
  }

  setFilter(filter: HistoryFilter): void {
    this.selectedHistoryFilter = filter;
    this.loadHistory();
  }

  loadHistory(): void {
    this.historyLoading = true;
    this.historyError = '';

    const request$ =
      this.selectedHistoryFilter === 'all'
        ? this.analysisService.getHistory()
        : this.analysisService.getHistory(this.selectedHistoryFilter);

    request$.subscribe({
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

  inputPreview(value: string): string {
    return value.length > 72 ? `${value.slice(0, 72)}...` : value;
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
    return risk.toUpperCase();
  }

  private utcDateStringHasTimezone(dateString: string): boolean {
    return /(?:Z|[+-]\d{2}:?\d{2})$/i.test(dateString);
  }
}
