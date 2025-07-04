// frontend_angular/src/app/chat/chat.service.ts
import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

export interface ChatMessage {
  role: 'user' | 'ai';
  content: string;
}

@Injectable({
  providedIn: 'root'
})
export class ChatService {
  private http = inject(HttpClient);
  // In a real app, this would come from an environment file
  private apiUrl = 'http://localhost:8000/api/chat';

  sendMessage(message: string): Observable<{ reply: string }> {
    return this.http.post<{ reply: string }>(this.apiUrl, { message });
  }
}