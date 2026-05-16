import { DecimalPipe } from '@angular/common';
import { Component, Input } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-hero-stats',
  standalone: true,
  imports: [DecimalPipe, RouterLink],
  templateUrl: './hero-stats.component.html'
})
export class HeroStatsComponent {
  @Input() totalAnalyses = 0;
  @Input() alertsCount = 0;
  @Input() riskRate = 0;
}
