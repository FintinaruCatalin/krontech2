import { DecimalPipe } from '@angular/common';
import { Component, Input } from '@angular/core';

@Component({
  selector: 'app-hero-stats',
  standalone: true,
  imports: [DecimalPipe],
  templateUrl: './hero-stats.component.html'
})
export class HeroStatsComponent {
  @Input() totalAnalyses = 0;
  @Input() alertsCount = 0;
  @Input() riskRate = 0;
}
