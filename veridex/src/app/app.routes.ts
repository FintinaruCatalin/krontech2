import { Routes } from '@angular/router';
import { AnalysisPageComponent } from './pages/analysis-page/analysis-page.component';
import { ExtensionInfoComponent } from './pages/extension-info/extension-info.component';
import { FakeNewsComponent } from './pages/fake-news/fake-news.component';
import { HowItWorksComponent } from './pages/how-it-works/how-it-works.component';

export const routes: Routes = [
  { path: '', component: AnalysisPageComponent },
  { path: 'how', component: HowItWorksComponent },
  { path: 'fake-news', component: FakeNewsComponent },
  { path: 'extension', component: ExtensionInfoComponent },
  { path: '**', redirectTo: '' }
];
