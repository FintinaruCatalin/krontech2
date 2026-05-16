import { Routes } from '@angular/router';
import { AnalysisPageComponent } from './pages/analysis-page/analysis-page.component';
import { ExtensionInfoComponent } from './pages/extension-info/extension-info.component';
import { FakeNewsComponent } from './pages/fake-news/fake-news.component';
import { HowItWorksComponent } from './pages/how-it-works/how-it-works.component';
import { HistoryComponent } from './components/history/history.component';
import { LoginComponent } from './login/login.component';
import { RegisterComponent } from './register/register.component';
import { authGuard } from './guards/auth.guard';

export const routes: Routes = [
  { path: '', component: AnalysisPageComponent, canActivate: [authGuard] },
  { path: 'analysis', component: AnalysisPageComponent, canActivate: [authGuard] },
  { path: 'login', component: LoginComponent },
  { path: 'register', component: RegisterComponent },
  { path: 'history', component: HistoryComponent, canActivate: [authGuard] },
  { path: 'how', component: HowItWorksComponent },
  { path: 'fake-news', component: FakeNewsComponent },
  { path: 'extension', component: ExtensionInfoComponent },
  { path: '**', redirectTo: '' }
];
