from django.contrib import admin

# Register your models here.
from .models import Post

class PostAdmin(admin.ModelAdmin):
	fieldsets = [
		(None, 				 {'fields':['post_title']}),
		('Date information', {'fields':['pub_date']}),# 'classes':['collapse']}),
		(None,				 {'fields':['post_content']}),
		('Slug',             {'fields':['post_slug']}), 
	]
	
	list_display = ('post_title', 'pub_date', 'was_published_recently', 'post_slug',)
	list_filter = ['pub_date']
	search_fields = ['post_title']

admin.site.register(Post, PostAdmin)
