import { Component, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'app-blog-post',
  template: `
    <article>
      <h2>{{ title }}</h2>
      <div [innerHTML] ="bodyHtml"></div>
    </article>
  `
})
export class BlogPostComponent implements OnInit {
  title = '';
  bodyHtml = '';

  constructor(private http: HttpClient) {}

  ngOnInit() {
    this.http.get<any>('/api/posts/latest').subscribe(post => {
      this.title = post.title;
      this.bodyHtml = post.body;
    });
  }
}
