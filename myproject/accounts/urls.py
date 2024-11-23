# Updated urls.py
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views 
from .views import (UserRegistrationView, VerifyOTPView, LoginView, logout_view, dashboard_view, profile_view, 
                    settings_view, AddToCartView,remove_from_cart, CartListView, PurchaseView, PurchaseHistoryView,
                      AddProductView, GetProductView, ProductUpdateView, ProductDeleteView, GetProductcartView, product_list,
                      ProductListView,get_cart_data, process_payment, get_product_prices, 
)

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='user-registration'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', logout_view, name='logout'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('profile/', profile_view, name='profile'),
    path('settings/', settings_view, name='settings'),
    path('add-product/', AddProductView.as_view(), name='add-product'),
    path('get-product/<int:product_id>/', GetProductcartView.as_view(), name='get-product'),
    path('check-superuser-status/', views.check_superuser_status, name='check_superuser_status'),
    path('products/', GetProductView.as_view(), name='get_product'),
    path('display-on-cart/', CartListView.as_view(), name='cart-list'),
    path('cart/add/', AddToCartView.as_view(), name='add-to-cart'),
    path('cart/remove/', views.remove_from_cart, name='remove_from_cart'),
    path('cart/clear/', views.clear_cart, name='clear_cart'),
    path('purchase/', PurchaseView.as_view(), name='purchase'),
    path('purchase/history/', PurchaseHistoryView.as_view(), name='purchase-history'),
    path('home/products/', product_list, name='product-list'),
    path('product/update/<int:product_id>/', ProductUpdateView.as_view(), name='product-update'),
    path('product/delete/<int:product_id>/', ProductDeleteView.as_view(), name='product-delete'),
    path('payment/products/', ProductListView.as_view(), name='payment-product-list'),
    path('get_cart_data/', views.get_cart_data, name='get_cart_data/'),
    path('payment/', views.process_payment, name='process_payment/'),
    path('get_product_prices/', views.get_product_prices, name='get_product_prices'),
    path('heck_authentication/', views.check_authentication, name='check_authentication'),
    # path('payment/', views.process_payment, name='payment'),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)