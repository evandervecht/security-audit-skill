import { Component, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import DOMPurify from 'dompurify';

@Component({
  selector: 'app-blog-post',
  template: `
    <article>
      <h2>{{ title }}</h2>
      <div class="post-body">{{ sanitizedBody }}</div>
    </article>
  `
})
export class BlogPostComponent implements OnInit {
  title = '';
  sanitizedBody = '';

  constructor(private http: HttpClient) {}

  ngOnInit() {
    this.http.get<any>('/api/posts/latest').subscribe(post => {
      this.title = post.title;
      this.sanitizedBody = DOMPurify.sanitize(post.body, {
        ALLOWED_TAGS: ['p', 'br', 'strong', 'em'],
        ALLOWED_ATTR: []
      });
    });
  }
}
