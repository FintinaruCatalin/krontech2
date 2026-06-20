import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

export type AnalysisRisk = 'safe' | 'suspicious' | 'dangerous';
export type ScanType = 'sms' | 'url';

export interface AnalysisResponse {
  trust_score: number;
  risk: AnalysisRisk;
  reasons: string[];
  recommendation: string;
}

export interface ScanHistoryItem {
  id: number;
  scan_type: ScanType;
  input_value: string;
  trust_score: number;
  risk: string;
  reasons: string[];
  recommendation: string;
  created_at: string;
}

export interface StatsResponse {
  total_analyses: number;
  alerts_generated: number;
  risk_rate: number;
}

@Injectable({
  providedIn: 'root'
})
export class AnalysisService {
  private readonly baseUrl = 'https://anti-scam-backend.onrender.com';

  constructor(private readonly http: HttpClient) {}

  analyzeSms(text: string): Observable<AnalysisResponse> {
    return this.http.post<AnalysisResponse>(`${this.baseUrl}/analyze/phishing`, { text });
  }

  analyzeUrl(url: string): Observable<AnalysisResponse> {
    return this.http.post<AnalysisResponse>(`${this.baseUrl}/analyze/url`, { url });
  }

  getHistory(scanType?: ScanType): Observable<ScanHistoryItem[]> {
    const options = scanType ? { params: { scan_type: scanType } } : {};

    return this.http.get<ScanHistoryItem[]>(`${this.baseUrl}/history`, options);
  }

  getStats(): Observable<StatsResponse> {
    return this.http.get<StatsResponse>(`${this.baseUrl}/stats`);
  }
}
