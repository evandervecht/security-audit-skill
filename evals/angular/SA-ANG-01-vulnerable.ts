import { Component } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'app-comment',
  template: `<div [innerHTML]="trustedComment"></div>`
})
export class CommentComponent {
  trustedComment: SafeHtml = '';

  constructor(private sanitizer: DomSanitizer) {}

  displayComment(userInput: string) {
    this.trustedComment = this.sanitizer.bypassSecurityTrustHtml(userInput);
  }
}
