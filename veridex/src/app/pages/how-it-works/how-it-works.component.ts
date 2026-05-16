import { Component } from '@angular/core';

@Component({
  selector: 'app-how-it-works',
  standalone: true,
  templateUrl: './how-it-works.component.html'
})
export class HowItWorksComponent {
  readonly steps = [
    {
      num: 1,
      title: 'Introducere input',
      desc: 'Utilizatorul introduce un SMS sau URL. Inputul este trimis securizat către backend.',
      badges: ['Angular', 'HttpClient', 'FastAPI']
    },
    {
      num: 2,
      title: 'Alegere endpoint',
      desc: 'Frontend-ul alege automat endpoint-ul potrivit: phishing pentru SMS sau url pentru linkuri.',
      badges: ['/analyze/phishing', '/analyze/url']
    },
    {
      num: 3,
      title: 'Analiză backend',
      desc: 'Backend-ul calculează scorul de încredere, riscul, motivele și recomandarea.',
      badges: ['trust_score', 'risk', 'reasons']
    },
    {
      num: 4,
      title: 'Rezultat clar',
      desc: 'Interfața afișează verdictul într-un card ușor de citit pe desktop și mobil.',
      badges: ['Responsive UI', 'PWA ready']
    }
  ];
}
