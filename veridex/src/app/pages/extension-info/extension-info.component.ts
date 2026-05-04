import { Component } from '@angular/core';

@Component({
  selector: 'app-extension-info',
  standalone: true,
  templateUrl: './extension-info.component.html'
})
export class ExtensionInfoComponent {
  readonly features = [
    { letter: 'A', title: 'Analiză automată', desc: 'Verificare în background pentru paginile vizitate.' },
    { letter: 'B', title: 'Avertizare vizibilă', desc: 'Mesaje clare când o pagină pare suspectă.' },
    { letter: 'C', title: 'Popup rapid', desc: 'Verdict și trust score direct din iconul extensiei.' },
    { letter: 'D', title: 'Raportare', desc: 'Flux simplu pentru raportarea linkurilor periculoase.' }
  ];
}
