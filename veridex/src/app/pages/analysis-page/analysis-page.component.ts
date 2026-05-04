import { Component, ViewChild } from '@angular/core';
import { ScanHistoryItem } from '../../analysis.service';
import { AnalysisFormComponent } from '../../components/analysis-form/analysis-form.component';
import { HeroStatsComponent } from '../../components/hero-stats/hero-stats.component';
import { HistoryComponent } from '../../components/history/history.component';

@Component({
  selector: 'app-analysis-page',
  standalone: true,
  imports: [HeroStatsComponent, AnalysisFormComponent, HistoryComponent],
  templateUrl: './analysis-page.component.html'
})
export class AnalysisPageComponent {
  @ViewChild(HistoryComponent) private historyComponent?: HistoryComponent;

  statsHistoryList: ScanHistoryItem[] = [];

  handleAnalysisCompleted(): void {
    this.historyComponent?.refresh();
  }

  updateStats(items: ScanHistoryItem[]): void {
    this.statsHistoryList = items;
  }

  totalAnalyses(): number {
    return this.statsHistoryList.length;
  }

  alertsCount(): number {
    return this.statsHistoryList.filter((item) => item.risk === 'dangerous' || item.risk === 'suspicious').length;
  }

  riskRate(): number {
    const totalAnalyses = this.totalAnalyses();

    return totalAnalyses === 0 ? 0 : (this.alertsCount() / totalAnalyses) * 100;
  }
}
