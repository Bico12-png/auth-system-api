from flask import Blueprint, request, jsonify
from src.models.key import db, Key, AccessLog
from datetime import datetime
import random

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/create_keys', methods=['POST'])
def create_keys():
    """Criar uma ou múltiplas chaves"""
    try:
        data = request.get_json()
        expiration_days = data.get('expiration_days', 30)
        quantity = data.get('quantity', 1)
        
        if quantity > 100:
            return jsonify({'error': 'Máximo de 100 chaves por vez'}), 400
        
        created_keys = []
        for _ in range(quantity):
            key_id = Key.generate_unique_key()
            new_key = Key(
                key_id=key_id,
                expiration_days=expiration_days
            )
            db.session.add(new_key)
            created_keys.append(key_id)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'{quantity} chave(s) criada(s) com sucesso',
            'keys': created_keys
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """Autenticar cliente com chave e HWID"""
    try:
        data = request.get_json()
        key_id = data.get('key_id')
        hwid = data.get('hwid')
        ip_address = request.remote_addr
        
        if not key_id or not hwid:
            log_entry = AccessLog(
                key_id=key_id or 'UNKNOWN',
                ip_address=ip_address,
                hwid_attempt=hwid,
                status='failure',
                message='Chave ou HWID não fornecidos'
            )
            db.session.add(log_entry)
            db.session.commit()
            return jsonify({'error': 'Chave e HWID são obrigatórios'}), 400
        
        # Buscar a chave
        key = Key.query.filter_by(key_id=key_id).first()
        
        if not key:
            log_entry = AccessLog(
                key_id=key_id,
                ip_address=ip_address,
                hwid_attempt=hwid,
                status='failure',
                message='Chave não encontrada'
            )
            db.session.add(log_entry)
            db.session.commit()
            return jsonify({'error': 'Chave inválida'}), 401
        
        if not key.is_active:
            log_entry = AccessLog(
                key_id=key_id,
                ip_address=ip_address,
                hwid_attempt=hwid,
                status='failure',
                message='Chave pausada'
            )
            db.session.add(log_entry)
            db.session.commit()
            return jsonify({'error': 'Chave pausada'}), 401
        
        # Primeiro login - registrar HWID
        if not key.hwid:
            key.hwid = hwid
            key.first_login_at = datetime.utcnow()
            db.session.commit()
            
            log_entry = AccessLog(
                key_id=key_id,
                ip_address=ip_address,
                hwid_attempt=hwid,
                status='success',
                message='Primeiro login realizado com sucesso'
            )
            db.session.add(log_entry)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Login realizado com sucesso',
                'first_login': True
            }), 200
        
        # Verificar se o HWID coincide
        if key.hwid != hwid:
            log_entry = AccessLog(
                key_id=key_id,
                ip_address=ip_address,
                hwid_attempt=hwid,
                status='failure',
                message='HWID não coincide'
            )
            db.session.add(log_entry)
            db.session.commit()
            return jsonify({'error': 'HWID não autorizado para esta chave'}), 401
        
        # Verificar se a chave expirou
        if key.is_expired():
            log_entry = AccessLog(
                key_id=key_id,
                ip_address=ip_address,
                hwid_attempt=hwid,
                status='failure',
                message='Chave expirada'
            )
            db.session.add(log_entry)
            db.session.commit()
            return jsonify({'error': 'Chave expirada'}), 401
        
        # Login bem-sucedido
        log_entry = AccessLog(
            key_id=key_id,
            ip_address=ip_address,
            hwid_attempt=hwid,
            status='success',
            message='Login realizado com sucesso'
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Login realizado com sucesso',
            'first_login': False
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/delete_key/<key_id>', methods=['DELETE'])
def delete_key(key_id):
    """Deletar uma chave específica"""
    try:
        key = Key.query.filter_by(key_id=key_id).first()
        
        if not key:
            return jsonify({'error': 'Chave não encontrada'}), 404
        
        # Deletar logs relacionados
        AccessLog.query.filter_by(key_id=key_id).delete()
        
        # Deletar a chave
        db.session.delete(key)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Chave {key_id} deletada com sucesso'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/delete_all_keys', methods=['DELETE'])
def delete_all_keys():
    """Deletar todas as chaves"""
    try:
        # Deletar todos os logs
        AccessLog.query.delete()
        
        # Deletar todas as chaves
        Key.query.delete()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Todas as chaves foram deletadas'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/keys', methods=['GET'])
def get_keys():
    """Listar todas as chaves e seus status"""
    try:
        keys = Key.query.all()
        keys_data = [key.to_dict() for key in keys]
        
        return jsonify({
            'success': True,
            'keys': keys_data,
            'total': len(keys_data)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/logs', methods=['GET'])
def get_logs():
    """Obter logs de acesso"""
    try:
        logs = AccessLog.query.order_by(AccessLog.login_at.desc()).limit(100).all()
        logs_data = [log.to_dict() for log in logs]
        
        return jsonify({
            'success': True,
            'logs': logs_data,
            'total': len(logs_data)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/pause_all_keys', methods=['POST'])
def pause_all_keys():
    """Pausar todas as chaves"""
    try:
        Key.query.update({'is_active': False})
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Todas as chaves foram pausadas'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/activate_all_keys', methods=['POST'])
def activate_all_keys():
    """Ativar todas as chaves"""
    try:
        Key.query.update({'is_active': True})
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Todas as chaves foram ativadas'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/reset_hwid/<key_id>', methods=['POST'])
def reset_hwid(key_id):
    """Resetar o HWID de uma chave específica"""
    try:
        key = Key.query.filter_by(key_id=key_id).first()
        
        if not key:
            return jsonify({'error': 'Chave não encontrada'}), 404
        
        key.hwid = None
        key.first_login_at = None
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'HWID da chave {key_id} foi resetado'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

