import { Component } from '@angular/core';
import DOMPurify from 'dompurify';

@Component({
  selector: 'app-comment',
  template: `<div class="comment-body">{{ sanitizedComment }}</div>`
})
export class CommentComponent {
  sanitizedComment: string = '';

  displayComment(userInput: string) {
    this.sanitizedComment = DOMPurify.sanitize(userInput, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
      ALLOWED_ATTR: []
    });
  }
}
