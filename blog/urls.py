from django.conf.urls import url

from . import views

urlpatterns = [
	#/blog/
	url(r'^$', views.IndexView.as_view(), name='index'),
	url(r'^(?P<pk>[0-9]{1})/$', views.DetailView.as_view(), name='detail'),
	#url(r'^(?P<pk>[0-9]+)/[a-z]/$', views.DetailView.as_view(), name='detail'),
	#/blog/2014
	url(r'^(?P<year>[0-9]{4})/$', views.YearView.as_view(), name='year'),
	#/blog/2014/05/
	url(r'^(?P<year>[0-9]{4})/(?P<month>[0-9]{2})/$', views.MonthView.as_view(month_format='%m'), name="month_numeric"),
	#/blog/2014/aug
	url(r'^(?P<year>[0-9]{4})/(?P<month>[-\w]+)/$', views.MonthView.as_view(), name="month"),
	url(r'^(?P<slug>[-\w]+)/$', views.DetailTestView.as_view(), name='detailtest'),
	#/blog/2014/05/26
	#url(r'^(?P<year>[0-9]{4}/(?P<month>[0-9]{2}/(?P<day>[0-9]{2}/$', views.article_detail), 
]
