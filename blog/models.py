import datetime
from django.db import models
from django.utils import timezone
from django.template.defaultfilters import slugify

class Post(models.Model):
	post_title = models.CharField(max_length=100, unique=True)
	post_content = models.TextField()
	pub_date = models.DateTimeField('date published')
	post_slug = models.SlugField(null=True, blank=True, unique=True)
	
	def __unicode__(self):
		return self.post_title
		
	def get_year(self):
		return self.pub_date.year
		
	def get_month(self):
		return self.pub_date.month
		
	def get_day(self):
		return self.pub_date.day
		
	def get_previous(self):
		return self.id - 1
		
	def get_next(self):
		return self.id + 1
		
	def was_published_recently(self):
		now = timezone.now()
		return now - datetime.timedelta(days=1) <= self.pub_date <= now
		
	def save(self, *args, **kwargs):
		if not self.id:
			if not self.post_slug:
				self.post_slug = slugify(self.post_title)
			
		super(Post, self).save(*args, **kwargs)
		
	was_published_recently.admin_order_field = 'pub_date'
	was_published_recently.boolean = True
	was_published_recently.short_description = 'Published recently?'
	



# Create your models here.
