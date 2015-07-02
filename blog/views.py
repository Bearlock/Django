from django.shortcuts           import get_object_or_404, render
from django.http                import HttpResponse, HttpResponseRedirect
from django.core.urlresolvers   import reverse
from django.views               import generic
from django.utils               import timezone
from django.core.paginator      import Paginator, EmptyPage
from django.views.generic.dates import YearArchiveView
from django.views.generic.dates import MonthArchiveView

from .models import Post
# Create your views here.

class IndexView(generic.ListView):
	model = Post
	date_field = "pub_date"
	template_name = 'blog/index.html'
	context_object_name = 'latest_post_list'
	
	def get_queryset(self):
		return Post.objects.filter(pub_date__lte=timezone.now()).order_by('-pub_date')
		
class DetailView(generic.DetailView):
	model = Post
	template_name = 'blog/detail.html'
	
	def get_queryset(self):
		"""
		Excludes any questions that aren't published yet.
		"""
		return Post.objects.filter(pub_date__lte=timezone.now())
		
class DetailTestView(DetailView):
	model = Post
	template_name = 'blog/detail.html'
	slug_field = 'post_slug'

	def get_queryset(self):
		"""
		Excludes any questions that aren't published yet.
		"""
		return Post.objects.filter(pub_date__lte=timezone.now())

class YearView(YearArchiveView):
	template_name ='blog/year.html'
	queryset = Post.objects.all()
	date_field = "pub_date"
	make_object_list = True
	allow_future = True
	
class MonthView(MonthArchiveView):
	template_name = 'blog/month.html'
	queryset = Post.objects.all()
	date_field = "pub_date"
	allow_future = True


# 	model = Post
# 	template_name = 'blog/year.html'
# 	context_object_name = 'year_list'
# 	
# 	def get_queryset(self):
# 		return Post.objects.filter(pub_date__year=year).order_by('pub_date')
	
#class DetailView(generic.DetailView):
#	model = Post