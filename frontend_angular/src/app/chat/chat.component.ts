// frontend_angular/src/app/chat/chat.component.ts
import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ChatService, ChatMessage } from './chat.service';

@Component({
  selector: 'app-chat',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './chat.component.html',
  styleUrl: './chat.component.css'
})
export class ChatComponent {
  private chatService = inject(ChatService);

  userInput = signal('');
  messages = signal<ChatMessage[]>([]);
  isLoading = signal(false);

  sendMessage() {
    const message = this.userInput().trim();
    if (!message) return;

    // Add user's message to the UI
    this.messages.update(current => [...current, { role: 'user', content: message }]);
    this.isLoading.set(true);
    this.userInput.set(''); // Clear input field

    // Send message to the backend
    this.chatService.sendMessage(message).subscribe({
      next: (response) => {
        // Add AI's response to the UI
        this.messages.update(current => [...current, { role: 'ai', content: response.reply }]);
        this.isLoading.set(false);
      },
      error: (err) => {
        console.error("Error sending message:", err);
        this.messages.update(current => [...current, { role: 'ai', content: 'Sorry, I encountered an error. Please try again.' }]);
        this.isLoading.set(false);
      }
    });
  }
}