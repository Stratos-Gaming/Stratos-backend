from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import InstagramPost
import json

# Create your views here.

@api_view(['POST'])
def instagram_webhook(request):
    try:
        # Parse the webhook data from IFTTT
        data = json.loads(request.body)
        
        # Extract post information from IFTTT payload
        post_data = {
            'caption': data.get('caption', ''),
            'media_url': data.get('media_url', ''),  # Video URL
            'img': data.get('img', ''),  # Image thumbnail
            'timestamp': data.get('timestamp', '')  # Store as is
        }
        
        # Create new post
        post = InstagramPost.objects.create(**post_data)
        
        return Response({
            'status': 'success',
            'message': 'Post created successfully',
            'timestamp': post.timestamp
        })
        
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=400)

@api_view(['GET'])
def get_instagram_posts(request):
    try:
        # Get the latest 3 posts
        posts = InstagramPost.objects.all()[:3]
        
        # Format the response
        posts_data = [{
            'caption': post.caption,
            'media_url': post.media_url,
            'img': post.img,
            'timestamp': post.timestamp
        } for post in posts]
        
        return Response({
            'status': 'success',
            'posts': posts_data
        })
        
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=500)
